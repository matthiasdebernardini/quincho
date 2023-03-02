use bitcoin::secp256k1;
use bitcoin::{Address, AddressType, PublicKey};
use std::str::FromStr;
use thiserror::Error;

// https://github.com/stevenroose/hal/blob/master/src/bin/hal/cmd/message.rs
pub fn verify(
    address: &str,
    message: &str,
    signature: &str,
    _electrum_legacy: bool,
) -> Result<bool, QuinchoError> {
    let signer = address;
    let signer_addr_res = Address::from_str(&signer);
    let signer_pubk_res = PublicKey::from_str(&signer);
    if signer_addr_res.is_err() && signer_pubk_res.is_err() {
        if let Err(e) = signer_addr_res {
            return Err(QuinchoError::SignerParsingError(e.to_string()));
        }
        if let Err(e) = signer_pubk_res {
            return Err(QuinchoError::PubkeyParsingError(e.to_string()));
        }
        return Err(QuinchoError::GeneralError(
            "Failed to parse signer.".to_string(),
        ));
    }
    if signer_addr_res.is_ok() && signer_pubk_res.is_ok() {
        return Err(QuinchoError::ImpossibleCaseError);
    }

    let sig = signature;

    let sig_bytes = match (hex::decode(&sig), base64::decode(&sig)) {
        (Ok(b), Err(_)) => b,
        (Err(_), Ok(b)) => b,
        (Ok(b), Ok(_)) => {
            eprintln!("Signature is both valid hex and base64, assuming it's hex.");
            b
        }
        (Err(e1), Err(e2)) => {
            return Err(QuinchoError::InvalidSigError(
                e1.to_string(),
                e2.to_string(),
            ))
        }
    };

    if sig_bytes.len() != 65 {
        return Err(QuinchoError::InvalidSigLengthError(
            sig_bytes.len().to_string(),
        ));
    }
    let recid = secp256k1::ecdsa::RecoveryId::from_i32(((sig_bytes[0] - 27) & 0x03) as i32)
        .expect("invalid recoverable signature (invalid recid)");
    let compressed = ((sig_bytes[0] - 27) & 0x04) != 0;
    let signature = secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_bytes[1..], recid)
        .expect("invalid recoverable signature");

    let msg = message;
    let hash = bitcoin::util::misc::signed_msg_hash(&msg);

    let secp = secp256k1::Secp256k1::verification_only();
    let pubkey = PublicKey {
        inner: secp
            .recover_ecdsa(&secp256k1::Message::from_slice(&hash).unwrap(), &signature)
            .expect("invalid signature"),
        compressed,
    };

    let network = Address::from_str(address)?.network;

    if let Ok(pk) = signer_pubk_res {
        if pubkey != pk {
            return Err(QuinchoError::PubkeyExpectationError(
                pubkey.to_string(),
                pk.to_string(),
            ));
        }
    } else if let Ok(expected) = signer_addr_res {
        let addr = match expected.address_type() {
            None => panic!("Unknown address type provided"),
            Some(AddressType::P2pkh) => Address::p2pkh(&pubkey, network),
            Some(AddressType::P2wpkh) => {
                Address::p2wpkh(&pubkey, network).expect("Uncompressed key in Segwit")
            }
            Some(AddressType::P2sh) => {
                Address::p2shwpkh(&pubkey, network).expect("Uncompressed key in Segwit")
            }
            Some(tp) => panic!("Address of type {} can't sign messages.", tp),
        };
        // We need to use to_string because regtest and testnet addresses are the same.
        if addr.to_string() != expected.to_string() {
            return Err(QuinchoError::AddressExpectationError(
                addr.to_string(),
                expected.to_string(),
                expected
                    .address_type()
                    .map(|t| t.to_string())
                    .unwrap()
                    .to_string(),
            ));
        }
    } else {
        unreachable!();
    }
    eprintln!("Signature is valid.");
    Ok(true)
}

#[derive(Error, Debug, Clone)]
pub enum QuinchoError {
    #[error("Rare/impossible case that signer can both be parsed as pubkey and address.")]
    ImpossibleCaseError,
    #[error("General e: `{0}`")]
    GeneralError(String),
    #[error("Secp e: `{0}`")]
    SecpError(String),
    #[error("Address e: `{0}`")]
    AddressError(String),
    #[error("Error parsing signer as address: `{0}`")]
    SignerParsingError(String),
    #[error("Invalid signature: `{0}` `{1}`")]
    InvalidSigError(String, String),
    #[error("Error parsing signer as public key: `{0}`")]
    PubkeyParsingError(String),
    #[error("Invalid signature: length is `{0}` instead of 65 bytes")]
    InvalidSigLengthError(String),
    #[error("Signed for pubkey `{0}`, expected `{1}`")]
    PubkeyExpectationError(String, String),
    #[error("Signed for address {0}, expected {1}, address type {2}")]
    AddressExpectationError(String, String, String),
}

impl From<bitcoin::util::address::Error> for QuinchoError {
    fn from(e: bitcoin::util::address::Error) -> Self {
        QuinchoError::AddressError(e.to_string())
    }
}

impl From<bitcoin::secp256k1::Error> for QuinchoError {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        QuinchoError::SecpError(e.to_string())
    }
}

// https://github.com/BitonicNL/verify-signed-message/blob/main/pkg/verify_test.go
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn electrum() {
        let passing_electrum = vec![("electrum legacy", "mj6gcWsSKMyTh7QALLSH5q6HEEiN4yBuXk", "The outage comes at a time when bitcoin has been fast approaching new highs not seen since June 26, 2019.", "Hw1c1NGI5cNYTfAeDSyH/yUt67R499dZlTyNDb/Wxz8uX7I8ECS39JP8HbGpk4wD5J3PsMDdAwywBag3X8f+mw0="),
                                                                     ("electrum segwit native",   "tb1qr97cuq4kvq7plfetmxnl6kls46xaka78n2288z",   "The outage comes at a time when bitcoin has been fast approaching new highs not seen since June 26, 2019.", "H/bSByRH7BW1YydfZlEx9x/nt4EAx/4A691CFlK1URbPEU5tJnTIu4emuzkgZFwC0ptvKuCnyBThnyLDCqPqT10=")];
        for (name, address, message, signature) in passing_electrum.iter() {
            let result = verify(address, message, signature, true).unwrap();
            assert_eq!(result, true, "{}", name);
        }
    }
    #[test]
    #[should_panic]
    fn failing() {
        let failing =
                vec![("address - checksum mismatch", "17u1mDkgNcDwi44braeTKpvnfNnTrgvBfB", "test signature", "IHfvfadyMsn/P0tKH6UnDnbYiZcOWWhk8xbGIWUOwTX75MR8LfEn9Mdxq5R2h1IRXKaFxbqR6SfC3sZrHBdA0Tg=", "could not decode address: checksum mismatch"),
         ("address - different", "14wPe34dikRzK4tMYvtwMMJCEZbJ7ar35V", "test message", "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=", "generated address '1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5' does not match expected address '14wPe34dikRzK4tMYvtwMMJCEZbJ7ar35V'"),
         ("address - invalid", "INVALID", "test message", "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=", "could not decode address: decoded address is of unknown format"),
         ("message - different", "14wPe34dikRzK4tMYvtwMMJCEZbJ7ar35V", "Totally different message, thus different calculated address", "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=", "generated address '1LwzpMrpDakgZ9XPCsSuGG6ZXCE3fkNdQR' does not match expected address '14wPe34dikRzK4tMYvtwMMJCEZbJ7ar35V'"),
         ("signature - invalid", "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5", "test message", "INVALID", "illegal base64 data at input byte 4"),
         ("signature - invalid curve", "1C9CRMGBYrGKKQ6eEpwm4dzMqkRZxPB5xa", "test", "IQt3ycjmA6LCbcTiFcj7o6odqX5PKeYPmL+dwcblLc/Xor1E2szTlEZKtHdzSrSz78PbYQUlX5a5VuDeSJLrEr0=", "could not recover pubkey: calculated Rx is larger than curve P"),
         ("signature - non-bitcoin", "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5", "test message", "zPOBbkXzwDgGVU3Gxk0noVuLq8P1pGfQUxnS0nzuxEN3qR/U/s63P81io7LV04ZxN88gVX/Qw0rzLFBR8q4IkUc=", "invalid recovery flag: 204"),
         ("signature - too short",   "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5", "test message", "VGhpcyBpcyBub3QgdmFsaWQ=", "wrong signature length: 17 instead of 65")];
        for (name, address, message, signature, reason) in failing.iter() {
            println!("{} fails because {}", name, reason);
            let result = verify(address, message, signature, false).unwrap();
            assert_eq!(result, true, "{}", name);
        }
    }
    #[test]
    fn passing() {
        let verylongmessage = "VeryLongMessage!".repeat(64);
        let passing =
        vec![("bitcoin core", "1CBHFokbnZVuq9fA3yjPTvSNXpdRRP7eUB", " Lorem ipsum dolor sit amet, consectetur adipiscing elit. In a turpis dignissim, tincidunt dolor quis, aliquam justo. Sed eleifend eleifend tempus. Sed blandit lectus at ullamcorper blandit. Quisque suscipit ligula lacus, tempor fringilla erat pharetra a. Curabitur pretium varius purus vel luctus. Donec fringilla velit vel risus fermentum, ac aliquam enim sollicitudin. Aliquam elementum, nunc nec malesuada fringilla, sem sem lacinia libero, id tempus nunc velit nec dui. Vestibulum gravida non tortor sit amet accumsan. Nunc semper vehicula vestibulum. Praesent at nibh dapibus, eleifend neque vitae, vehicula justo. Nam ultricies at orci vel laoreet. Morbi metus sapien, pulvinar ut dui ut, malesuada lobortis odio. Curabitur eget diam ligula. Nunc vel nisl consectetur, elementum magna et, elementum erat. Maecenas risus massa, mattis a sapien sed, molestie ullamcorper sapien. ", "H3HQ9gwAMCee0T7M8fZTgvIYlG6pMnpP41ioDUTKjlPsOMHwrF3qmgsM+kFoWLL1u6P4ZUf3nwYacPCeBjrzFzE="),
             ("bms compressed legacy", "14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY", "test message", "H/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="),
             ("bms compressed p2pkh", "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5", "test message", "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA="),
             ("bms uncompressed legacy", "1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD", "test message", "G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4="),
             ("bms uncompressed p2pkh", "19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T", "test message", "HFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA="),
             ("coinomi legacy", "1PjSDaSiVdWW6YjwFA6FHwwfqkZdPEJUZv", "Test message!", "IK7I33rASHdSeYDotQ9WfO4jrxgdl5ef/bTbX6Q5PNtFY9rJeAHfoZV5GpDO1K3OqoPs8ROZRXPyMNLkVOxJ+Rc="),
             ("coinomi segwit", "39FT3L2wH56h2jmae5abPU1A7nVs6QyApV", "Test message!", "HzpoLFjr+eUPkseb+i0Vaqj7FRm5o1+Ei/kae7XWN6nmFLmvLi7uWicerYNXjCMUf3nCnm/9UPb6SYJLI60Nh8A="),
             ("coinomi segwit native", "bc1q0utxws6ptfdfcvaz29y4st065t5ku6vcqd364f", "Test message!", "H+G7Fz3EVxX02kIker4HPgnP8Mlf3bT52p81hnNAahTOGJ8ANSaU0bF5RsprgTH6LXLx/PmCka48Ov7OrPw2bms="),
             // ("electrum legacy", "1CPBDkm8ER3o7r2HANcvNoVHsBYKcUHTp9", "Integer can be encoded depending on the represented value to save space. Variable length integers always precede an array/vector of a type of data that may vary in length. Longer numbers are encoded in little endian. If you're reading the Satoshi client code (BitcoinQT) it refers to this encoding as a \"CompactSize\". Modern Bitcoin Core also has the VARINT macro which implements an even more compact integer for the purpose of local storage (which is incompatible with \"CompactSize\" described here). VARINT is not a part of the protocol.", "IHTr8YSzZ17Ut/Qaaui6BvGd42+TGwVwNYaIMUAZQTZRSqDtaTfsOcaOllPstp3IxzMlpXVOzLxNZE8r8ieffnY="),
             // ("electrum legacy with spaces", "1CPBDkm8ER3o7r2HANcvNoVHsBYKcUHTp9", "   Three spaces both sides   ", "H0X6iDaOzAVqUndwAl8Ca1k8T+zbzDpfrEaXbh/FlF08bDsquG5oPnnFIfWU/8Z46jfFUwlWLfDK1iRU/DHZ6n8="),
             ("electrum segwit native",  "bc1qsdjne3y6ljndzvg9z9qrhje8k7p2m5yas704hn", "Integer can be encoded depending on the represented value to save space. Variable length integers always precede an array/vector of a type of data that may vary in length. Longer numbers are encoded in little endian. If you're reading the Satoshi client code (BitcoinQT) it refers to this encoding as a \"CompactSize\". Modern Bitcoin Core also has the VARINT macro which implements an even more compact integer for the purpose of local storage (which is incompatible with \"CompactSize\" described here). VARINT is not a part of the protocol.", "H3TkHAXCKRfyDowCra5YRDF/Vkk2HQCel/pgEgTj9LYaWpnviSRcuYtv/CZk7NTyHsJnYP56bqbvuU3PejwLCnA="),
             ("mycelium legacy", "13VwTBVLNpNSQVTrYpuHQVJYnk2y2Nr1ue", "Test message!", "Hxpnr2oDFTjivFkrrp89UoMrzaAzFkkEciS3MUHCfdoEXN/KvHi9ii2Xz+FuQ6KjlZDlaPb197E8TWnhIAzbT0M="),
             ("mycelium segwit", "325ZMWMu9vaWQeUG8Gc8MzsVKzt3Rqn8H7", "Test message!", "IM/bkqpERGRFDGgxnceinULcqz1iRVBSUVlnDPZRKHGUQMC5t1P5wRp2/1b1+rpjFHhSS2pExB88cA750PNRlaw="),
             ("mycelium segwit native", "bc1q58dh2fpwms37g29nw979pa65lsvjkqxq82jzvv", "Test message!", "ILNax/LC+m3WwzIhnrieNN8DRzWTAgcVStSJmwdabUQII2fIlYUlEgnlNf4j2G4yJQoO4zFqCwaLOX4PDj1XwjA="),
             ("python-bitcoinlib p2pkh", "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G", "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G", "H85WKpqtNZDrajOnYDgUY+abh0KCAcOsAIOQwx2PftAbLEPRA7mzXA/CjXRxzz0MC225pR/hx02Vf2Ag2x33kU4="),
             ("samourai - legacy", "1JSjyW3dZSQHv6jb6u6baXLUZnsThqmzf4", "hello foo", "INAP+PMyI2vqIxiEKIcPOaaffspU3gAPm0YWhCxJr5iqWbQwqns9+RiXIzuU9JoNQs/MQ1BZ4O2XM23utyw3jr0="),
             ("samourai segwit native",   "bc1qnxhkjd3kcjdzqz4u0m47xj3dne907cd8yg7qdr",   "hello foo", "IJruGdQX+V6s+zvzTD3msz2l1obPchx19/bsefr+QGihcRArLSzXtkoUXA8k0NkBsIpFXGRxbG/s+eimZ+eGg70="),
             ("trezor p2pkh",  "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL",   "This is an example of a signed message.", "IP2PL321I4/N0HfVIEw+aUnCYdcAJpzvwdnS3O9rlQI2MO5hf2yKz560DI7dcEycp06kr8OT9D81tOiVgyTL3Rw="),
             ("trezor p2pkh long message", "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL", &verylongmessage, "IApGR2zrhNBu9XhIKAJvkiyIFfV6rIN7jAEwB8qKhGDbY++Rfb6669EIscgUu+6m2x8rIkGpWOU/5xXMhrGZ2cM="),
             ("trezor segwit native", "bc1qannfxke2tfd4l7vhepehpvt05y83v3qsf6nfkk", "This is an example of a signed message.", "KLVddgDZ6afipJFV3fPP2455bCB/qrgzAQ+kH7eCiIm8R89iNIp6qgkjwIMqWJ+rVB6PEutU+3EckOIwfw9msZQ="),
             ("trezor segwit native long message", "bc1qannfxke2tfd4l7vhepehpvt05y83v3qsf6nfkk", &verylongmessage, "KMb4biVeqnaMRH1jXZHaAWMaxUryI8LBgtT6NnbP7K5KGZrTOnT+BPtGw5QyrLjYPedNqQ9fARI7O32LwlK8f3E="),
             // ("trezor segwit", "3L6TyTisPBmrDAj6RoKmDzNnj4eQi54gD2", "This is an example of a signed message.", "I3RN5FFvrFwUCAgBVmRRajL+rZTeiXdc7H4k28JP4TMHWsCTAcTMjhl76ktkgWYdW46b8Z2Le4o4Ls21PC7gdQ0="),
             // ("trezor segwit long message",  "3L6TyTisPBmrDAj6RoKmDzNnj4eQi54gD2", &verylongmessage, "I26t7jgGhPcHScUhQciqfDtq/YTQ5fOM+nGCPzsRBaXzTiODSlu28jn/KK2H9An0TkzmJpdUrcADiLGVB6XZOG8="),
             ("uncompressed p2pkh short message", "18J72YSM9pKLvyXX1XAjFXA98zeEvxBYmw", "Test123", "Gzhfsw0ItSrrTCChykFhPujeTyAcvVxiXwywxpHmkwFiKuUR2ETbaoFcocmcSshrtdIjfm8oXlJoTOLosZp3Yc8="),
             // ("uncompressed p2pkh long message", "18J72YSM9pKLvyXX1XAjFXA98zeEvxBYmw"," Lorem ipsum dolor sit amet, consectetur adipiscing elit. In a turpis dignissim, tincidunt dolor quis, aliquam justo. Sed eleifend eleifend tempus. Sed blandit lectus at ullamcorper blandit. Quisque suscipit ligula lacus, tempor fringilla erat pharetra a. Curabitur pretium varius purus vel luctus. Donec fringilla velit vel risus fermentum, ac aliquam enim sollicitudin. Aliquam elementum, nunc nec malesuada fringilla, sem sem lacinia libero, id tempus nunc velit nec dui. Vestibulum gravida non tortor sit amet accumsan. Nunc semper vehicula vestibulum. Praesent at nibh dapibus, eleifend neque vitae, vehicula justo. Nam ultricies at orci vel laoreet. Morbi metus sapien, pulvinar ut dui ut, malesuada lobortis odio. Curabitur eget diam ligula. Nunc vel nisl consectetur, elementum magna et, elementum erat. Maecenas risus massa, mattis a sapien sed, molestie ullamcorper sapien. ", "HHOGSz6AUEEyVGoCUw1GqQ5qy9KvW5uO1FfqWLbwYxkQVsI+sbM0jpBQWkyjr72166yiL/LQEtW3SpVBR1gXdYY=")
             ];

        for (name, address, message, signature) in passing.iter() {
            let result: bool;
            if name.contains("electrum legacy") {
                result = verify(address, message, signature, true)
                    .expect(format!("{} failed", name).as_str());
            } else {
                result = verify(address, message, signature, false)
                    .expect(format!("{} failed", name).as_str());
            }

            assert_eq!(result, true, "{}", name);
        }
    }
}
