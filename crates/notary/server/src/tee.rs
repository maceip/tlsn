use serde::{Deserialize, Serialize};
use sgx_dcap_ql_rs::quote3_error_t;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};
use tracing::{debug, error, instrument};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quote {
    raw_quote: String,
    mrsigner: String,
    mrenclave: String,
}

impl Default for Quote {
    fn default() -> Quote {
        Quote {
            raw_quote: "".to_string(),
            mrsigner: "".to_string(),
            mrenclave: "".to_string(),
        }
    }
}

impl std::fmt::Debug for QuoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuoteError::IoError(err) => write!(f, "IoError: {:?}", err),
            QuoteError::IntelQuote3Error(err) => write!(f, "IntelQuote3Error: {}", *err as u8),
        }
    }
}

impl From<io::Error> for QuoteError {
    fn from(err: io::Error) -> QuoteError {
        QuoteError::IoError(err)
    }
}

enum QuoteError {
    IoError(io::Error),
    IntelQuote3Error(quote3_error_t),
}

#[instrument(level = "debug", skip_all)]
async fn gramine_quote() -> Result<Quote, QuoteError> {
    //// Check if the the gramine pseudo-hardware exists
    if !Path::new("/dev/attestation/quote").exists() {
        error!("Failed to retrieve quote hardware");
        return Err(QuoteError::IntelQuote3Error(
            quote3_error_t::SGX_QL_ERROR_UNEXPECTED,
        ));
    }

    // Reading attestation type
    let mut attestation_file = File::open("/dev/attestation/attestation_type")?;
    let mut attestation_type = String::new();
    attestation_file.read_to_string(&mut attestation_type)?;
    debug!("Detected attestation type: {}", attestation_type);

    //// Writing 64 zero bytes to the gramine report pseudo-hardware `/dev/attestation/user_report_data`
    let mut report_data_file = OpenOptions::new()
        .write(true)
        .open("/dev/attestation/user_report_data")?;
    report_data_file.write_all(&[0u8; 64])?;

    //// Reading from the gramine quote pseudo-hardware `/dev/attestation/quote`
    let mut quote_file = File::open("/dev/attestation/quote")?;
    let mut quote = Vec::new();
    quote_file.read_to_end(&mut quote)?;

    if quote.len() < 432 {
        error!("Quote data is too short, expected at least 432 bytes");
        return Err(QuoteError::IntelQuote3Error(
            quote3_error_t::SGX_QL_ERROR_UNEXPECTED,
        ));
    }

    //// Extract MRENCLAVE and MRSIGNER
    //// https://github.com/intel/linux-sgx/blob/main/common/inc/sgx_quote.h
    let mrenclave = hex::encode(&quote[112..144]);
    let mrsigner = hex::encode(&quote[176..208]);

    debug!("MRENCLAVE: {}", mrenclave);
    debug!("MRSIGNER: {}", mrsigner);

    //// Return the Quote struct with the extracted data
    Ok(Quote {
        raw_quote: hex::encode(quote),
        mrsigner: mrsigner,
        mrenclave: mrenclave,
    })
}

pub async fn quote() -> Quote {
    //// tee-detection logic will live here, for now its only gramine-sgx
    match gramine_quote().await {
        Ok(quote) => quote,
        Err(err) => {
            error!("Failed to retrieve quote: {:?}", err);
            match err {
                QuoteError::IoError(_) => {
                    //// error hamdle
                    return Quote::default();
                }
                QuoteError::IntelQuote3Error(_) => {
                    //// error hamdle
                    return Quote::default();
                }
            }
        }
    }
}
