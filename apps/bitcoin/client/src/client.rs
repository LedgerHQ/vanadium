use std::str::FromStr;

use bitcoin::bip32::DerivationPath;
use common::fastpsbt::{
    PSBT_GLOBAL_SP_DLEQ, PSBT_GLOBAL_SP_ECDH_SHARE, PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_IN_MUSIG2_PARTIAL_SIG, PSBT_IN_MUSIG2_PUB_NONCE, PSBT_IN_PARTIAL_SIG, PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_SCRIPT_SIG, PSBT_OUT_SCRIPT,
};
use common::message::{
    self, IdentitySignature, MuSig2PartialSignature, MuSig2Pubnonce, PartialSignature, Request,
    Response, SilentPaymentOutputScript, SilentPaymentShare,
};
use common::por::{ProofOfRegistration, RegistrationId};
use common::psbt::PsbtV2;
use sdk::vanadium_client::{VAppExecutionError, VAppTransport};

use sdk::comm::SendMessageError;

#[derive(Debug)]
pub enum BitcoinClientError {
    VAppExecutionError(VAppExecutionError),
    SendMessageError(SendMessageError),
    AppError(common::errors::Error), // the V-App returned an error response
    InvalidResponse(String),         // the V-App response was an unexpected type
    GenericError(String),
}

impl From<VAppExecutionError> for BitcoinClientError {
    fn from(e: VAppExecutionError) -> Self {
        Self::VAppExecutionError(e)
    }
}

impl From<SendMessageError> for BitcoinClientError {
    fn from(e: SendMessageError) -> Self {
        Self::SendMessageError(e)
    }
}

impl From<&'static str> for BitcoinClientError {
    fn from(e: &'static str) -> Self {
        Self::GenericError(e.to_string())
    }
}

impl From<common::bip388::ParseError> for BitcoinClientError {
    fn from(e: common::bip388::ParseError) -> Self {
        Self::GenericError(format!("{:?}", e))
    }
}

impl From<String> for BitcoinClientError {
    fn from(e: String) -> Self {
        Self::GenericError(e)
    }
}

impl std::fmt::Display for BitcoinClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitcoinClientError::VAppExecutionError(e) => write!(f, "VAppExecutionError: {}", e),
            BitcoinClientError::SendMessageError(e) => write!(f, "SendMessageError: {}", e),
            BitcoinClientError::AppError(e) => write!(f, "AppError: {}", e),
            BitcoinClientError::InvalidResponse(e) => write!(f, "InvalidResponse: {}", e),
            BitcoinClientError::GenericError(e) => write!(f, "GenericError: {}", e),
        }
    }
}

impl std::error::Error for BitcoinClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BitcoinClientError::VAppExecutionError(e) => Some(e),
            BitcoinClientError::SendMessageError(e) => Some(e),
            Self::AppError(_) => None,
            BitcoinClientError::InvalidResponse(_) => None,
            BitcoinClientError::GenericError(_) => None,
        }
    }
}

pub struct BitcoinClient {
    vapp_transport: Box<dyn VAppTransport + Send>,
}

impl<'a> BitcoinClient {
    pub fn new(vapp_transport: Box<dyn VAppTransport + Send>) -> Self {
        Self { vapp_transport }
    }

    async fn send_message(&mut self, out: &[u8]) -> Result<Vec<u8>, BitcoinClientError> {
        sdk::comm::send_message(&mut self.vapp_transport, out)
            .await
            .map_err(BitcoinClientError::from)
    }

    // Parse app response; if the response is a Response::Error, it is converted to BitcoinClientError::AppError.
    async fn parse_response(response_raw: &'a [u8]) -> Result<Response, BitcoinClientError> {
        let mut decoder = minicbor::Decoder::new(response_raw);
        let resp: Response = decoder.decode().map_err(|_| {
            BitcoinClientError::GenericError("Failed to parse response".to_string())
        })?;
        if decoder.position() != response_raw.len() {
            return Err(BitcoinClientError::GenericError(
                "Failed to parse response".to_string(),
            ));
        }
        if let Response::Error { error } = resp {
            return Err(BitcoinClientError::AppError(error));
        }
        Ok(resp)
    }

    pub async fn exit(&mut self) -> Result<i32, BitcoinClientError> {
        let msg = minicbor::to_vec(&Request::Exit).map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize Exit request".to_string())
        })?;

        match self.send_message(&msg).await {
            Ok(_) => {
                return Err(BitcoinClientError::GenericError(
                    "exit shouldn't return a response".to_string(),
                ));
            }
            Err(e) => match e {
                BitcoinClientError::SendMessageError(SendMessageError::VAppExecutionError(
                    VAppExecutionError::AppExited(status),
                )) => Ok(status),
                e => Err(BitcoinClientError::InvalidResponse(format!(
                    "Unexpected error on exit: {:?}",
                    e
                ))),
            },
        }
    }

    pub async fn get_master_fingerprint(
        &mut self,
        tree: message::KeyTree,
    ) -> Result<u32, BitcoinClientError> {
        let msg = minicbor::to_vec(&Request::GetMasterFingerprint { tree }).map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize GetMasterFingerprint request".to_string(),
            )
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::MasterFingerprint { fingerprint } => Ok(fingerprint),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    pub async fn get_extended_pubkey(
        &mut self,
        tree: message::KeyTree,
        bip32_path: &str,
        display: bool,
        identity_index: Option<u32>,
    ) -> Result<([u8; 78], Option<IdentitySignature>), BitcoinClientError> {
        let path = DerivationPath::from_str(bip32_path)
            .map_err(|e| format!("Failed to convert bip32_path: {}", e))?;

        let msg = minicbor::to_vec(&Request::GetExtendedPubkey {
            tree,
            display,
            path: message::Bip32Path(path.to_u32_vec()),
            identity_index,
        })
        .map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize GetExtendedPubkey request".to_string(),
            )
        })?;
        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::ExtendedPubkey { xpub, identity_sig } => {
                let arr: [u8; 78] = xpub.as_slice().try_into().map_err(|_| {
                    BitcoinClientError::InvalidResponse("Invalid pubkey length".to_string())
                })?;
                Ok((arr, identity_sig))
            }
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Gets the i-th identity public key (xpub at path `m/1229210958'/i`).
    pub async fn get_identity_key(
        &mut self,
        index: Option<u32>,
        display: bool,
    ) -> Result<[u8; 78], BitcoinClientError> {
        let path = common::identity::identity_derivation_path(index);
        let msg = minicbor::to_vec(&Request::GetExtendedPubkey {
            tree: message::KeyTree::Standard,
            display,
            path: message::Bip32Path(path),
            identity_index: None,
        })
        .map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize GetExtendedPubkey request".to_string(),
            )
        })?;
        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::ExtendedPubkey { xpub, .. } => {
                let arr: [u8; 78] = xpub.as_slice().try_into().map_err(|_| {
                    BitcoinClientError::InvalidResponse("Invalid pubkey length".to_string())
                })?;
                Ok(arr)
            }
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    pub async fn register_account(
        &mut self,
        name: &str,
        account: &message::Account,
        registered_identities: Option<Vec<message::RegisteredIdentityEntry>>,
        key_signatures: Option<Vec<Option<message::IdentitySignature>>>,
        show_cleartext: bool,
    ) -> Result<
        (
            RegistrationId<common::bip388::WalletPolicy>,
            ProofOfRegistration<common::bip388::WalletPolicy>,
        ),
        BitcoinClientError,
    > {
        let msg = minicbor::to_vec(&Request::RegisterAccount {
            name: name.into(),
            account: account.clone(),
            registered_identities,
            key_signatures,
            show_cleartext,
        })
        .map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize RegisterAccount request".to_string(),
            )
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::AccountRegistered { account_id, hmac } => Ok((
                RegistrationId::from_bytes(account_id),
                ProofOfRegistration::from_bytes(hmac),
            )),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    pub async fn register_identity_key(
        &mut self,
        name: &str,
        pubkey: &[u8; 33],
    ) -> Result<
        (
            RegistrationId<common::identity::IdentityKey>,
            ProofOfRegistration<common::identity::IdentityKey>,
        ),
        BitcoinClientError,
    > {
        let msg = minicbor::to_vec(&Request::RegisterIdentityKey {
            name: name.into(),
            pubkey: pubkey.to_vec(),
        })
        .map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize RegisterIdentityKey request".to_string(),
            )
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::IdentityKeyRegistered { key_id, hmac } => Ok((
                RegistrationId::from_bytes(key_id),
                ProofOfRegistration::from_bytes(hmac),
            )),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    pub async fn get_address(
        &mut self,
        account: &message::Account,
        name: &str,
        coords: &message::AccountCoordinates,
        por: Option<&ProofOfRegistration<common::bip388::WalletPolicy>>,
        display: bool,
        identity_index: Option<u32>,
    ) -> Result<(String, Option<IdentitySignature>), BitcoinClientError> {
        let msg = minicbor::to_vec(&Request::GetAddress {
            display,
            name: Some(name.to_string()),
            account: account.clone(),
            por: por
                .map(|p| p.dangerous_as_bytes().to_vec())
                .unwrap_or(vec![]),
            coordinates: coords.clone(),
            identity_index,
        })
        .map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize GetAddress request".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::Address {
                address,
                identity_sig,
            } => Ok((address, identity_sig)),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Calls the V-App's `SignPsbt`. Behaviour depends on the PSBT contents:
    /// - Inputs whose wallet policy uses plain placeholders the device
    ///   controls → ECDSA / Schnorr partial signatures land in `signatures`.
    /// - Inputs with a `musig(...)` placeholder the device participates in →
    ///   - if the PSBT already carries this device's pubnonce
    ///     (BIP-373 `PSBT_IN_MUSIG2_PUB_NONCE`) → a round-2 partial signature
    ///     lands in `musig_partial_sigs`;
    ///   - otherwise → a round-1 pubnonce lands in `musig_pubnonces`, and the
    ///     host is expected to merge it with cosigners' nonces into the PSBT
    ///     and re-send for round 2.
    pub async fn sign_psbt(
        &mut self,
        psbt: &[u8],
    ) -> Result<SignedPsbtResponse, BitcoinClientError> {
        let msg = minicbor::to_vec(&Request::SignPsbt {
            psbt: psbt.to_vec(),
        })
        .map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize SignPsbt request".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::PsbtSigned {
                signatures,
                musig_pubnonces,
                musig_partial_sigs,
                sp_shares,
                sp_output_scripts,
            } => Ok(SignedPsbtResponse {
                signatures,
                musig_pubnonces,
                musig_partial_sigs,
                sp_shares,
                sp_output_scripts,
            }),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }
}

/// All signing material the V-App can return from a single `SignPsbt` request.
///
/// `signatures` covers ECDSA and Schnorr partial signatures for plain key
/// placeholders. The two `musig_*` fields are non-empty only for PSBTs that
/// involve `musig(...)` placeholders this device participates in — see
/// [`BitcoinClient::sign_psbt`] for the round 1 / round 2 dispatch. The two `sp_*`
/// fields are non-empty only for PSBTs that pay to silent payment codes: the
/// signatures commit to those scripts, so they must be set in the PSBT too.
#[derive(Debug, Clone)]
pub struct SignedPsbtResponse {
    pub signatures: Vec<PartialSignature>,
    pub musig_pubnonces: Vec<MuSig2Pubnonce>,
    pub musig_partial_sigs: Vec<MuSig2PartialSignature>,
    pub sp_shares: Vec<SilentPaymentShare>,
    pub sp_output_scripts: Vec<SilentPaymentOutputScript>,
}

impl SignedPsbtResponse {
    /// Adds this response to `psbt`, the PSBT that the device signed:
    ///
    /// - each partial signature as `PSBT_IN_PARTIAL_SIG`, `PSBT_IN_TAP_KEY_SIG` or
    ///   `PSBT_IN_TAP_SCRIPT_SIG`;
    /// - the MuSig2 pubnonces and partial signatures as `PSBT_IN_MUSIG2_PUB_NONCE` and
    ///   `PSBT_IN_MUSIG2_PARTIAL_SIG` (BIP-373);
    /// - the ECDH shares as `PSBT_GLOBAL_SP_ECDH_SHARE` and `PSBT_GLOBAL_SP_DLEQ`, and the scripts
    ///   of the outputs to silent payment codes as `PSBT_OUT_SCRIPT` (BIP-375).
    ///
    /// It also updates `PSBT_GLOBAL_TX_MODIFIABLE`, as BIP-370 asks of a signer: the device signs
    /// with `SIGHASH_ALL` or `SIGHASH_DEFAULT`, so once the response has a signature, neither the
    /// inputs nor the outputs can be modified. With scripts of outputs to silent payment codes, the
    /// field becomes 0 as BIP-375 asks: those scripts depend on all the inputs.
    pub fn merge_into(&self, psbt: &mut PsbtV2) -> Result<(), BitcoinClientError> {
        let invalid = |what: &str| BitcoinClientError::InvalidResponse(format!("Invalid {}", what));

        for sig in &self.signatures {
            let input = psbt
                .inputs
                .get_mut(sig.input_index as usize)
                .ok_or_else(|| invalid("input index"))?;
            match (sig.pubkey.len(), &sig.leaf_hash) {
                (33, None) => input.insert(PSBT_IN_PARTIAL_SIG, &sig.pubkey, sig.signature.clone()),
                (32, None) => input.insert(PSBT_IN_TAP_KEY_SIG, &[], sig.signature.clone()),
                (32, Some(leaf_hash)) if leaf_hash.len() == 32 => input.insert(
                    PSBT_IN_TAP_SCRIPT_SIG,
                    &[&sig.pubkey[..], leaf_hash].concat(),
                    sig.signature.clone(),
                ),
                _ => return Err(invalid("partial signature")),
            };
        }

        // BIP-373 keys: the participant's key, the aggregate key, then the leaf hash, if any
        let musig_key = |participant: &[u8; 33], aggregate: &[u8; 33], leaf: &Option<[u8; 32]>| {
            let mut key = [&participant[..], &aggregate[..]].concat();
            key.extend(leaf.iter().flatten());
            key
        };
        for pn in &self.musig_pubnonces {
            psbt.inputs
                .get_mut(pn.input_index as usize)
                .ok_or_else(|| invalid("input index"))?
                .insert(
                    PSBT_IN_MUSIG2_PUB_NONCE,
                    &musig_key(&pn.participant_pk, &pn.aggregate_pubkey, &pn.leaf_hash),
                    pn.pubnonce.to_vec(),
                );
        }
        for ps in &self.musig_partial_sigs {
            psbt.inputs
                .get_mut(ps.input_index as usize)
                .ok_or_else(|| invalid("input index"))?
                .insert(
                    PSBT_IN_MUSIG2_PARTIAL_SIG,
                    &musig_key(&ps.participant_pk, &ps.aggregate_pubkey, &ps.leaf_hash),
                    ps.signature.to_vec(),
                );
        }

        for share in &self.sp_shares {
            psbt.global.insert(
                PSBT_GLOBAL_SP_ECDH_SHARE,
                &share.scan_key,
                share.share.to_vec(),
            );
            psbt.global.insert(
                PSBT_GLOBAL_SP_DLEQ,
                &share.scan_key,
                share.dleq_proof.to_vec(),
            );
        }
        for script in &self.sp_output_scripts {
            psbt.outputs
                .get_mut(script.output_index as usize)
                .ok_or_else(|| invalid("output index"))?
                .insert(PSBT_OUT_SCRIPT, &[], script.script.clone());
        }
        if !self.sp_output_scripts.is_empty() {
            // Inputs and outputs can't be modified anymore, and the third flag, which tells that
            // an input has SIGHASH_SINGLE, can't be set with silent payment outputs. A missing
            // field would mean the same, but BIP-375's reference validator wants it present.
            psbt.global.insert(PSBT_GLOBAL_TX_MODIFIABLE, &[], vec![0]);
        } else if !self.signatures.is_empty() || !self.musig_partial_sigs.is_empty() {
            // A missing field already means that nothing can be modified, and a pubnonce doesn't
            // commit to the transaction. The third flag tells about the other signers' signatures.
            if let Some(flags) = psbt.global.get(PSBT_GLOBAL_TX_MODIFIABLE, &[]) {
                let &[flags] = flags else {
                    return Err(BitcoinClientError::GenericError(
                        "Invalid PSBT_GLOBAL_TX_MODIFIABLE".into(),
                    ));
                };
                psbt.global
                    .insert(PSBT_GLOBAL_TX_MODIFIABLE, &[], vec![flags & !0b11]);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use common::fastpsbt::{self, PSBT_OUT_SP_V0_INFO};

    fn psbt() -> PsbtV2 {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default(); 2],
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1000),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
                };
                2
            ],
        };
        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap();
        PsbtV2::from_v0(&psbt.serialize()).unwrap()
    }

    fn response() -> SignedPsbtResponse {
        SignedPsbtResponse {
            signatures: vec![
                PartialSignature {
                    input_index: 0,
                    signature: vec![0x30, 1, 2, 0x01],
                    pubkey: vec![0x02; 33],
                    leaf_hash: None,
                },
                PartialSignature {
                    input_index: 1,
                    signature: vec![7; 64],
                    pubkey: vec![8; 32],
                    leaf_hash: Some(vec![9; 32]),
                },
            ],
            musig_pubnonces: vec![MuSig2Pubnonce {
                input_index: 1,
                pubnonce: [4; 66],
                participant_pk: [0x02; 33],
                aggregate_pubkey: [0x03; 33],
                leaf_hash: None,
            }],
            musig_partial_sigs: vec![],
            sp_shares: vec![SilentPaymentShare {
                scan_key: [0x02; 33],
                share: [0x03; 33],
                dleq_proof: [5; 64],
            }],
            sp_output_scripts: vec![SilentPaymentOutputScript {
                output_index: 1,
                script: [&[0x51, 0x20][..], &[6; 32]].concat(),
            }],
        }
    }

    #[test]
    fn merge_into() {
        let mut psbt = psbt();
        psbt.global
            .insert(PSBT_GLOBAL_TX_MODIFIABLE, &[], vec![0b111]);
        // an output to a silent payment code, which gets its script from the response
        let output = &mut psbt.outputs[1];
        output.remove(PSBT_OUT_SCRIPT, &[]);
        output.insert(PSBT_OUT_SP_V0_INFO, &[], vec![0x02; 66]);

        response().merge_into(&mut psbt).unwrap();

        assert_eq!(
            psbt.inputs[0].get(PSBT_IN_PARTIAL_SIG, &[0x02; 33]),
            Some(&[0x30, 1, 2, 0x01][..])
        );
        let script_sig_key = [[8; 32], [9; 32]].concat();
        assert_eq!(
            psbt.inputs[1].get(PSBT_IN_TAP_SCRIPT_SIG, &script_sig_key),
            Some(&[7; 64][..])
        );
        let nonce_key = [[0x02; 33], [0x03; 33]].concat();
        assert_eq!(
            psbt.inputs[1].get(PSBT_IN_MUSIG2_PUB_NONCE, &nonce_key),
            Some(&[4; 66][..])
        );
        assert_eq!(
            psbt.global.get(PSBT_GLOBAL_TX_MODIFIABLE, &[]),
            Some(&[0][..])
        );

        // fastpsbt reads the shares, and an output with both a script and a code
        let raw = psbt.serialize();
        let parsed = fastpsbt::Psbt::parse(&raw).unwrap();
        assert_eq!(parsed.get_sp_ecdh_share(&[0x02; 33]), Some(&[0x03; 33]));
        assert_eq!(parsed.get_sp_dleq_proof(&[0x02; 33]), Some(&[5; 64]));
        assert_eq!(
            parsed.output_script(1),
            Some(&[&[0x51, 0x20][..], &[6; 32]].concat()[..])
        );

        // the field is written when the PSBT doesn't have it
        let mut psbt = self::psbt();
        response().merge_into(&mut psbt).unwrap();
        assert_eq!(
            psbt.global.get(PSBT_GLOBAL_TX_MODIFIABLE, &[]),
            Some(&[0][..])
        );

        let mut bad = response();
        bad.signatures[0].input_index = 2;
        assert!(bad.merge_into(&mut self::psbt()).is_err());
        let mut bad = response();
        bad.signatures[0].pubkey = vec![2; 31];
        assert!(bad.merge_into(&mut self::psbt()).is_err());
        let mut bad = response();
        bad.sp_output_scripts[0].output_index = 2;
        assert!(bad.merge_into(&mut self::psbt()).is_err());
    }

    /// Without outputs to silent payment codes, a signature clears the flags that let the inputs
    /// and the outputs be modified, and keeps the flag of SIGHASH_SINGLE; a pubnonce doesn't.
    #[test]
    fn merge_into_clears_modifiable_flags() {
        let merged = |response: &SignedPsbtResponse, flags: Option<u8>| {
            let mut psbt = psbt();
            if let Some(flags) = flags {
                psbt.global
                    .insert(PSBT_GLOBAL_TX_MODIFIABLE, &[], vec![flags]);
            }
            response.merge_into(&mut psbt).unwrap();
            psbt.global
                .get(PSBT_GLOBAL_TX_MODIFIABLE, &[])
                .map(|flags| flags.to_vec())
        };
        let no_sp = SignedPsbtResponse {
            sp_shares: vec![],
            sp_output_scripts: vec![],
            ..response()
        };

        let signatures = SignedPsbtResponse {
            musig_pubnonces: vec![],
            ..no_sp.clone()
        };
        assert_eq!(merged(&signatures, Some(0b111)), Some(vec![0b100]));
        assert_eq!(merged(&signatures, Some(0b011)), Some(vec![0]));
        assert_eq!(merged(&signatures, None), None);

        let musig_partial_sig = SignedPsbtResponse {
            signatures: vec![],
            musig_pubnonces: vec![],
            musig_partial_sigs: vec![MuSig2PartialSignature {
                input_index: 1,
                signature: [4; 32],
                participant_pk: [0x02; 33],
                aggregate_pubkey: [0x03; 33],
                leaf_hash: None,
            }],
            ..no_sp.clone()
        };
        assert_eq!(merged(&musig_partial_sig, Some(0b011)), Some(vec![0]));

        let pubnonce = SignedPsbtResponse {
            signatures: vec![],
            ..no_sp
        };
        assert_eq!(merged(&pubnonce, Some(0b011)), Some(vec![0b011]));

        let mut psbt = psbt();
        psbt.global
            .insert(PSBT_GLOBAL_TX_MODIFIABLE, &[], vec![0, 0]);
        assert!(signatures.merge_into(&mut psbt).is_err());
    }
}
