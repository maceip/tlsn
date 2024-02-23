use futures::AsyncWriteExt;
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use spansy::http::parse_response;
use tlsn_core::{proof::SessionInfo, Direction, RedactedTranscript};
use tlsn_prover::tls::{Prover, ProverConfig};
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    let (_, (sent, received, _session_info)) = tokio::join!(prover(socket_0), verifier(socket_1));

    // assert_eq!(sent.authed(), &RangeSet::from(0..sent.data().len() - 1));
    // assert_eq!(
    //     sent.redacted(),
    //     &RangeSet::from(sent.data().len() - 1..sent.data().len())
    // );

    // assert_eq!(received.authed(), &RangeSet::from(2..received.data().len()));
    // assert_eq!(received.redacted(), &RangeSet::from(0..2));

    println!("Successfully verified");
    println!(
        "sent: {:#?}",
        String::from_utf8(sent.data().to_vec()).unwrap()
    );
    println!(
        "Received: {:#?}",
        String::from_utf8(received.data().to_vec()).unwrap()
    );
}

#[instrument(skip(verifier_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(verifier_socket: T) {
    const SERVER_DOMAIN: &str = "notary.pse.dev";

    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    let prover = Prover::new(
        ProverConfig::builder()
            .id("test")
            .server_dns(SERVER_DOMAIN)
            .build()
            .unwrap(),
    )
    .setup(verifier_socket.compat())
    .await
    .unwrap();

    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();

    let connection_task = tokio::spawn(connection.without_shutdown());

    let request = Request::builder()
        .uri(format!("https://{}/info", SERVER_DOMAIN))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("GET")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    let tls_connection = connection_task.await.unwrap().unwrap().io.into_inner();
    tls_connection.compat().close().await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_prove();

    let sent_transcript_len = prover.sent_transcript().data().len();
    let recv_transcript_len = prover.recv_transcript().data().len();

    let received_string = String::from_utf8(prover.recv_transcript().data().to_vec()).unwrap();
    let response = parse_response(prover.recv_transcript().data()).unwrap();
    let body = response.body.map_or(String::new(), |body| {
        String::from_utf8_lossy(body.as_bytes()).to_string()
    });
    let json = serde_json::from_str::<InfoResponse>(body.as_str()).unwrap();
    // println!("received: {:?}", &json);

    let commit_hash = json.git_commit_hash;
    let commit_hash_start = received_string.find(&commit_hash).unwrap();

    // Reveal parts of the transcript
    _ = prover.reveal(0..sent_transcript_len, Direction::Sent);
    _ = prover.reveal(0..commit_hash_start, Direction::Received);
    _ = prover.reveal(
        commit_hash_start + commit_hash.len()..recv_transcript_len,
        Direction::Received,
    );
    prover.prove().await.unwrap();

    prover.finalize().await.unwrap()
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> (RedactedTranscript, RedactedTranscript, SessionInfo) {
    let verifier_config = VerifierConfig::builder().id("test").build().unwrap();
    let verifier = Verifier::new(verifier_config);

    let (sent, received, session_info) = verifier.verify(socket.compat()).await.unwrap();
    (sent, received, session_info)
}

/// Response object of the /info API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoResponse {
    /// Current version of notary-server
    pub version: String,
    /// Public key of the notary signing key
    pub public_key: String,
    /// Current git commit hash of notary-server
    pub git_commit_hash: String,
    /// Current git commit timestamp of notary-server
    pub git_commit_timestamp: String,
}
