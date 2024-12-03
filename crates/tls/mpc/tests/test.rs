use std::{sync::Arc, time::Duration};

use futures::{AsyncReadExt, AsyncWriteExt};
use mpz_common::{
    executor::mt::{MTConfig, MTExecutor},
    Context, Flush,
};
use mpz_core::Block;
use mpz_fields::{gf2_128::Gf2_128, p256::P256, Field};
use mpz_garble::protocol::semihonest::{Evaluator, Generator};
use mpz_memory_core::{binary::Binary, correlated::Delta, Memory, View};
use mpz_ole::{ROLEReceiver, ROLESender, Receiver as RandomOLEReceiver, Sender as RandomOLESender};
use mpz_ot::{
    chou_orlandi::{Receiver as BaseReceiver, Sender as BaseSender},
    cot::{COTReceiver, COTSender, DerandCOTReceiver, DerandCOTSender},
    kos::{Receiver as KOSReceiver, ReceiverConfig, Sender as KOSSender, SenderConfig},
    rot::{
        any::{AnyReceiver, AnySender},
        randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender},
        ROTReceiver, ROTSender,
    },
};
use mpz_share_conversion::ShareConvert;
use mpz_vm_core::{Execute, Vm};
use rand::{distributions::Standard, prelude::Distribution, rngs::StdRng, SeedableRng};
use serio::{Deserialize, Serialize, StreamExt};
use tls_client::Certificate;
use tls_client_async::bind_client;
use tls_mpc::{
    build_follower, build_leader, MpcTlsCommonConfig, MpcTlsFollower, MpcTlsFollowerConfig,
    MpcTlsLeader, MpcTlsLeaderConfig, TlsRole,
};
use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::TokioAsyncReadCompatExt;
use uid_mux::{
    test_utils::{test_framed_mux, TestFramedMux},
    FramedUidMux,
};

fn create_vm<Ctx>(
    sender: impl COTSender<Block> + Flush<Ctx> + Send + 'static,
    receiver: impl COTReceiver<bool, Block, Future: Send> + Flush<Ctx> + Send + 'static,
) -> (
    impl Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx>,
    impl Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx>,
)
where
    Ctx: Context + 'static,
{
    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);

    let gen = Generator::new(sender, [0u8; 16], delta);
    let ev = Evaluator::new(receiver);

    (gen, ev)
}

fn create_ole<Ctx, F>(
    sender: impl ROTSender<[F; 2]> + Flush<Ctx> + Send,
    receiver: impl ROTReceiver<bool, F> + Flush<Ctx> + Send,
) -> (
    impl ROLESender<F> + Flush<Ctx> + Send,
    impl ROLEReceiver<F> + Flush<Ctx> + Send,
)
where
    F: Field + Serialize + Deserialize,
    Ctx: Context,
{
    let mut rng = StdRng::seed_from_u64(1);
    let seed = Block::random(&mut rng);

    let role_sender = RandomOLESender::new(seed, sender);
    let role_receiver = RandomOLEReceiver::new(receiver);

    (role_sender, role_receiver)
}

fn create_rot<Ctx, F: Field>(
    delta: Block,
) -> (
    impl ROTSender<[F; 2]> + Flush<Ctx>,
    impl ROTReceiver<bool, F> + Flush<Ctx>,
)
where
    Ctx: Context,
    Standard: Distribution<F>,
{
    let sender = KOSSender::new(SenderConfig::default(), delta, BaseReceiver::default());
    let receiver = KOSReceiver::new(ReceiverConfig::default(), BaseSender::default());

    let sender = RandomizeRCOTSender::new(sender);
    let receiver = RandomizeRCOTReceiver::new(receiver);

    let sender = AnySender::new(sender);
    let receiver = AnyReceiver::new(receiver);

    (sender, receiver)
}

const OT_SETUP_COUNT: usize = 1_000_000;

async fn leader<Ctx>(
    config: MpcTlsCommonConfig,
    rs_p_0: impl ROLESender<P256> + Flush<Ctx> + Send,
    rr_p_1: impl ROLEReceiver<P256> + Flush<Ctx> + Send,
    rs_gf_0: impl ROLESender<Gf2_128> + Flush<Ctx> + Send,
    rs_gf_1: impl ROLESender<Gf2_128> + Flush<Ctx> + Send,
    mux: TestFramedMux,
    ctx: Ctx,
    vm: impl Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
) where
    Ctx: Context + Send,
{
    let config = MTConfig::default();
    let mut rng = StdRng::seed_from_u64(0);

    let (ke, prf, cipher, encrypter, decrypter) =
        build_leader::<Ctx, _, _, _, _>(rs_p_0, rr_p_1, rs_gf_0, rs_gf_1);

    let common_config = MpcTlsCommonConfig::builder().build().unwrap();
    let mut leader = MpcTlsLeader::<_, _, _, _, Ctx, _>::new(
        MpcTlsLeaderConfig::builder()
            .common(common_config)
            .defer_decryption_from_start(false)
            .build()
            .unwrap(),
        Box::new(StreamExt::compat_stream(
            mux.open_framed(b"mpc_tls").await.unwrap(),
        )),
        ke,
        prf,
        cipher,
        encrypter,
        decrypter,
        ctx,
        vm,
    );

    leader.setup().await.unwrap();

    let (leader_ctrl, leader_fut) = leader.run();
    tokio::spawn(async { leader_fut.await.unwrap() });

    let mut root_store = tls_client::RootCertStore::empty();
    root_store.add(&Certificate(CA_CERT_DER.to_vec())).unwrap();
    let config = tls_client::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = SERVER_DOMAIN.try_into().unwrap();

    let client = tls_client::ClientConnection::new(
        Arc::new(config),
        Box::new(leader_ctrl.clone()),
        server_name,
    )
    .unwrap();

    let (client_socket, server_socket) = tokio::io::duplex(1 << 16);

    tokio::spawn(bind_test_server_hyper(server_socket.compat()));

    let (mut conn, conn_fut) = bind_client(client_socket.compat(), client);

    tokio::spawn(async { conn_fut.await.unwrap() });

    let msg = concat!(
        "POST /echo HTTP/1.1\r\n",
        "Host: test-server.io\r\n",
        "Connection: keep-alive\r\n",
        "Accept-Encoding: identity\r\n",
        "Content-Length: 5\r\n",
        "\r\n",
        "hello",
        "\r\n"
    );

    conn.write_all(msg.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 48];
    conn.read_exact(&mut buf).await.unwrap();

    println!("{}", String::from_utf8_lossy(&buf));

    leader_ctrl.defer_decryption().await.unwrap();

    let msg = concat!(
        "POST /echo HTTP/1.1\r\n",
        "Host: test-server.io\r\n",
        "Connection: close\r\n",
        "Accept-Encoding: identity\r\n",
        "Content-Length: 5\r\n",
        "\r\n",
        "hello",
        "\r\n"
    );

    conn.write_all(msg.as_bytes()).await.unwrap();

    // Wait for the server to reply.
    tokio::time::sleep(Duration::from_millis(100)).await;

    leader_ctrl.commit().await.unwrap();

    let mut buf = vec![0u8; 1024];
    conn.read_to_end(&mut buf).await.unwrap();

    leader_ctrl.close_connection().await.unwrap();
    conn.close().await.unwrap();

    //vm.finalize().await.unwrap();
}

async fn follower<Ctx>(
    config: MpcTlsCommonConfig,
    rs_p_1: impl ROLESender<P256> + Flush<Ctx> + Send,
    rr_p_0: impl ROLEReceiver<P256> + Flush<Ctx> + Send,
    rr_gf_0: impl ROLEReceiver<Gf2_128> + Flush<Ctx> + Send,
    rr_gf_1: impl ROLEReceiver<Gf2_128> + Flush<Ctx> + Send,
    mux: TestFramedMux,
    ctx: Ctx,
    vm: impl Vm<Binary> + View<Binary> + Memory<Binary> + Execute<Ctx> + Send,
) where
    Ctx: Context + Send,
{
    let config = MTConfig::default();
    let mut rng = StdRng::seed_from_u64(1);

    let (ke, prf, cipher, encrypter, decrypter) =
        build_follower::<Ctx, _, _, _, _>(rs_p_1, rr_p_0, rr_gf_0, rr_gf_1);

    let common_config = MpcTlsCommonConfig::builder().build().unwrap();
    let mut follower = MpcTlsFollower::<_, _, _, _, Ctx, _>::new(
        MpcTlsFollowerConfig::builder()
            .common(common_config)
            .build()
            .unwrap(),
        Box::new(StreamExt::compat_stream(
            mux.open_framed(b"mpc_tls").await.unwrap(),
        )),
        ke,
        prf,
        cipher,
        encrypter,
        decrypter,
        ctx,
        vm,
    );

    follower.setup().await.unwrap();

    let (_, fut) = follower.run();
    fut.await.unwrap();

    // vm.finalize().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn test() {
    tracing_subscriber::fmt::init();

    let mut rng = StdRng::seed_from_u64(0);
    let delta = Block::random(&mut rng);

    let sender = KOSSender::new(SenderConfig::default(), delta, BaseReceiver::default());
    let receiver = KOSReceiver::new(ReceiverConfig::default(), BaseSender::default());

    let (ot_sender, ot_receiver) = create_rot::<_, P256>(Block::random(&mut rng));
    let (p256_sender_0, p256_receiver_0) = create_ole::<_, P256>(ot_sender, ot_receiver);

    let (ot_sender, ot_receiver) = create_rot(Block::random(&mut rng));
    let (p256_sender_1, p256_receiver_1) = create_ole::<_, P256>(ot_sender, ot_receiver);

    let (ot_sender, ot_receiver) = create_rot(Block::random(&mut rng));
    let (gf2_sender_0, gf2_receiver_0) = create_ole::<_, Gf2_128>(ot_sender, ot_receiver);

    let (ot_sender, ot_receiver) = create_rot(Block::random(&mut rng));
    let (gf2_sender_1, gf2_receiver_1) = create_ole::<_, Gf2_128>(ot_sender, ot_receiver);

    let sender = DerandCOTSender::new(sender);
    let receiver = DerandCOTReceiver::new(receiver);
    let (gen, ev) = create_vm(sender, receiver);

    let common_config = MpcTlsCommonConfig::builder().build().unwrap();
    let (leader_mux, follower_mux) = test_framed_mux(8);

    let mt_config = MTConfig::default();
    let (ctx_leader, ctx_follower) = futures::try_join!(
        MTExecutor::new(leader_mux.clone(), mt_config.clone()).new_thread(),
        MTExecutor::new(follower_mux.clone(), mt_config).new_thread()
    )
    .unwrap();

    tokio::join!(
        leader(
            common_config.clone(),
            p256_sender_0,
            p256_receiver_1,
            gf2_sender_0,
            gf2_sender_1,
            leader_mux,
            ctx_leader,
            gen
        ),
        follower(
            common_config.clone(),
            p256_sender_1,
            p256_receiver_0,
            gf2_receiver_0,
            gf2_receiver_1,
            follower_mux,
            ctx_follower,
            ev
        ),
    );
}
