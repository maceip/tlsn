use crate::domain::notary::NotaryGlobals;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use axum_macros::debug_handler;
use serde::Serialize;
use sgx_dcap_ql_rs::{quote3_error_t, sgx_report_t, sgx_target_info_t};
use tracing::{debug, error, instrument};

#[derive(Serialize)]
struct QuoteBytesResponse {
    quote: Vec<u8>,
}

#[instrument(level = "debug", skip_all)]
async fn sgx_quote(
    State(_notary_globals): State<NotaryGlobals>,
) -> Result<Vec<u8>, quote3_error_t> {
    let sgx_report: sgx_report_t = Default::default();

    let (result, sgx_quote) = sgx_dcap_ql_rs::sgx_qe_get_quote(&sgx_report);

    if result != sgx_dcap_ql_rs::quote3_error_t::SGX_QL_SUCCESS {
        error!("Failed to retrieve quote");
        return Err(result);
    }
    if let Some(q) = sgx_quote {
        debug!("Quote data: {:?}", q);
        Ok(q) // Return q directly without wrapping in Option
    } else {
        debug!("Failed to retrieve quote.");
        Err(quote3_error_t::SGX_QL_ERROR_UNEXPECTED)
    }
}

#[debug_handler(state = NotaryGlobals)]
pub async fn quote(State(notary_globals): State<NotaryGlobals>) -> Response {
    let mut target_info: sgx_target_info_t = Default::default();

    //// sgx_qe_get_target_info() warms the QE and the result isnt used
    //// if sgx_get_quote() returns SGX_QL_ATT_KEY_NOT_INITIALIZED we could
    //// call sgx_qe_get_target_info() again, but that err code can be a
    //// few other things so correctly handling it will be tricky, failing is probably better for now.
    //// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
    let _result = sgx_dcap_ql_rs::sgx_qe_get_target_info(&mut target_info);

    match sgx_quote(State(notary_globals)).await {
        Ok(quote) => (StatusCode::OK, Json(QuoteBytesResponse { quote })).into_response(),
        Err(code) => (StatusCode::INTERNAL_SERVER_ERROR, (code as u8).to_string()).into_response(),
    }
}
