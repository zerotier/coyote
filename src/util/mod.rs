use rand::Fill;

const DEFAULT_NONCE_SIZE: usize = 64;

// generate some random bytes
pub(crate) fn make_nonce(len: Option<usize>) -> String {
    let mut r = Vec::new();
    r.resize(len.unwrap_or(DEFAULT_NONCE_SIZE), 0);

    r.try_fill(&mut rand::thread_rng())
        .expect("Couldn't do a random");

    base64::encode_config(r, base64::URL_SAFE_NO_PAD)
}

pub(crate) fn to_base64<T>(payload: &T) -> Result<String, serde_json::Error>
where
    T: serde::Serialize + ?Sized,
{
    Ok(base64::encode_config(
        serde_json::to_string(payload)?,
        base64::URL_SAFE_NO_PAD,
    ))
}
