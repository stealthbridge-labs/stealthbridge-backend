//! Testnet fee-paying relayer for smart-account creation.
//!
//! The relayer only *pays fees* for `SmartAccountFactory::create_account`,
//! which is permissionless and binds the customer's own keys in the account
//! constructor. The relayer key therefore has no authority over any customer
//! account, and the backend never sees a customer private key: the browser
//! supplies only the passkey's public key.
//!
//! Pure transaction assembly and signing live here and are unit tested; the
//! network flow (`deploy_account`) talks to Stellar RPC through the bounded
//! client in `AppState` and refuses to run against anything but Testnet.

use crate::server::AppState;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, BytesM, ContractId, DecoratedSignature, Hash, HostFunction, InvokeContractArgs,
    InvokeHostFunctionOp, LedgerEntryData, LedgerKey, LedgerKeyAccount, Limits, Memo, MuxedAccount,
    Operation, OperationBody, Preconditions, PublicKey, ReadXdr, ScAddress, ScSymbol, ScVal, ScVec,
    SequenceNumber, Signature, SignatureHint, SorobanTransactionData, Transaction,
    TransactionEnvelope, TransactionExt, TransactionSignaturePayload,
    TransactionSignaturePayloadTaggedTransaction, TransactionV1Envelope, Uint256, WriteXdr,
};

pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
/// Local quickstart network; accepted only with STEALTHBRIDGE_ALLOW_LOCAL_NETWORK=true.
pub const STANDALONE_PASSPHRASE: &str = "Standalone Network ; February 2017";

pub fn local_network_allowed() -> bool {
    std::env::var("STEALTHBRIDGE_ALLOW_LOCAL_NETWORK").as_deref() == Ok("true")
}

/// The relayer only ever signs for Testnet, or a local network when explicitly
/// enabled. The public network is never accepted.
pub fn allowed_network(passphrase: &str) -> bool {
    passphrase == TESTNET_PASSPHRASE
        || (passphrase == STANDALONE_PASSPHRASE && local_network_allowed())
}

/// Passphrase reported by the configured RPC, if it is an allowed network.
pub async fn network_passphrase(state: &AppState) -> Result<String, RelayError> {
    let net = state.rpc("getNetwork").await.map_err(|_| RelayError::Rpc)?;
    let p = net["passphrase"].as_str().ok_or(RelayError::Rpc)?;
    if allowed_network(p) {
        Ok(p.to_owned())
    } else {
        Err(RelayError::NotTestnet)
    }
}
const BASE_FEE: u32 = 100_000;
const MAX_TOTAL_FEE: u32 = 20_000_000; // 2 XLM hard ceiling per relayed tx

#[derive(Debug, PartialEq, Eq)]
pub enum RelayError {
    InvalidInput,
    NotTestnet,
    Rpc,
    Simulation,
    FeeTooHigh,
    Rejected,
    Timeout,
}

/// A smart-account signer key, mirroring the contract's `SignerKey` enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerKey {
    Ed25519([u8; 32]),
    Secp256r1([u8; 65]),
}

impl SignerKey {
    pub fn to_scval(&self) -> ScVal {
        let (tag, bytes): (&str, &[u8]) = match self {
            SignerKey::Ed25519(k) => ("Ed25519", k),
            SignerKey::Secp256r1(k) => ("Secp256r1", k),
        };
        ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol(tag.try_into().unwrap())),
                ScVal::Bytes(bytes.to_vec().try_into().unwrap()),
            ]
            .try_into()
            .unwrap(),
        )))
    }

    /// Uncompressed SEC1 P-256 point: 0x04 || X || Y.
    pub fn secp256r1_from_hex(hex_key: &str) -> Option<Self> {
        let raw = hex::decode(hex_key).ok()?;
        let arr: [u8; 65] = raw.try_into().ok()?;
        (arr[0] == 0x04).then_some(SignerKey::Secp256r1(arr))
    }
}

pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

pub fn contract_hash(contract: &str) -> Option<[u8; 32]> {
    stellar_strkey::Contract::from_string(contract)
        .ok()
        .map(|c| c.0)
}

/// Relayer signing key from an `S...` strkey secret seed.
pub fn relayer_key(secret: &str) -> Option<SigningKey> {
    let seed = stellar_strkey::ed25519::PrivateKey::from_string(secret).ok()?;
    Some(SigningKey::from_bytes(&seed.0))
}

/// Unsigned `create_account` invocation, before simulation.
pub fn create_account_tx(
    relayer: [u8; 32],
    sequence: i64,
    factory: &str,
    owner: &SignerKey,
    rp_hash: [u8; 32],
    guardian: Option<&SignerKey>,
) -> Option<Transaction> {
    let args: Vec<ScVal> = vec![
        owner.to_scval(),
        ScVal::Bytes(rp_hash.to_vec().try_into().ok()?),
        guardian.map(SignerKey::to_scval).unwrap_or(ScVal::Void),
    ];
    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash(contract_hash(factory)?))),
                function_name: ScSymbol("create_account".try_into().ok()?),
                args: args.try_into().ok()?,
            }),
            auth: vec![].try_into().ok()?,
        }),
    };
    Some(Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(relayer)),
        fee: BASE_FEE,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![op].try_into().ok()?,
        ext: TransactionExt::V0,
    })
}

/// Applies a successful `simulateTransaction` result: resources footprint,
/// resource fee and (empty) auth. Refuses simulations that require any
/// authorization, because factory creation must be permissionless.
fn simulated_resources(sim: &Value) -> Result<(SorobanTransactionData, u32), RelayError> {
    if sim.get("error").is_some_and(|e| !e.is_null()) {
        return Err(RelayError::Simulation);
    }
    let data_b64 = sim["transactionData"]
        .as_str()
        .ok_or(RelayError::Simulation)?;
    let data_bytes = crate::governance_code::decode_base64_bounded(data_b64, 64 * 1024)
        .map_err(|_| RelayError::Simulation)?;
    let data = SorobanTransactionData::from_xdr(&data_bytes, Limits::len(data_bytes.len()))
        .map_err(|_| RelayError::Simulation)?;
    let resource_fee: u32 = sim["minResourceFee"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or(RelayError::Simulation)?;
    Ok((data, resource_fee))
}

fn apply_resources(
    mut tx: Transaction,
    data: SorobanTransactionData,
    resource_fee: u32,
) -> Result<Transaction, RelayError> {
    // 15% headroom over the simulated resource fee, capped.
    let total = BASE_FEE
        .checked_add(resource_fee.saturating_add(resource_fee / 100 * 15))
        .ok_or(RelayError::FeeTooHigh)?;
    if total > MAX_TOTAL_FEE {
        return Err(RelayError::FeeTooHigh);
    }
    tx.fee = total;
    tx.ext = TransactionExt::V1(data);
    Ok(tx)
}

/// Applies a successful recording-mode simulation for an operation that must
/// need NO authorization (e.g. permissionless factory creation).
pub fn assemble(tx: Transaction, sim: &Value) -> Result<Transaction, RelayError> {
    let (data, fee) = simulated_resources(sim)?;
    let auth = sim["results"][0]["auth"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    if auth != 0 {
        return Err(RelayError::Rejected);
    }
    apply_resources(tx, data, fee)
}

/// Applies an enforcing-mode simulation of a transaction that already carries
/// its signed authorization entries.
pub fn assemble_signed(tx: Transaction, sim: &Value) -> Result<Transaction, RelayError> {
    let (data, fee) = simulated_resources(sim)?;
    apply_resources(tx, data, fee)
}

pub fn sign(tx: Transaction, passphrase: &str, key: &SigningKey) -> TransactionEnvelope {
    let payload = TransactionSignaturePayload {
        network_id: Hash(network_id(passphrase)),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };
    let digest: [u8; 32] = Sha256::digest(payload.to_xdr(Limits::none()).unwrap()).into();
    let signature = key.sign(&digest).to_bytes();
    let public = key.verifying_key().to_bytes();
    let hint = SignatureHint([public[28], public[29], public[30], public[31]]);
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![DecoratedSignature {
            hint,
            signature: Signature(BytesM::try_from(signature.to_vec()).unwrap()),
        }]
        .try_into()
        .unwrap(),
    })
}

pub fn transaction_hash(tx: &Transaction, passphrase: &str) -> String {
    let payload = TransactionSignaturePayload {
        network_id: Hash(network_id(passphrase)),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };
    hex::encode(Sha256::digest(payload.to_xdr(Limits::none()).unwrap()))
}

pub fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                T[((n >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

/// Contract address returned by a simulated or executed `create_account`.
pub fn returned_contract(retval_b64: &str) -> Option<String> {
    let bytes = crate::governance_code::decode_base64_bounded(retval_b64, 4096).ok()?;
    match ScVal::from_xdr(&bytes, Limits::len(bytes.len())).ok()? {
        ScVal::Address(ScAddress::Contract(ContractId(Hash(h)))) => {
            Some(stellar_strkey::Contract(h).to_string().as_str().to_owned())
        }
        _ => None,
    }
}

pub(crate) async fn relayer_sequence(
    state: &AppState,
    relayer: [u8; 32],
) -> Result<i64, RelayError> {
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(relayer))),
    });
    let key_b64 = b64(&key.to_xdr(Limits::none()).map_err(|_| RelayError::Rpc)?);
    let res = state
        .rpc_with_params("getLedgerEntries", Some(json!({"keys":[key_b64]})))
        .await
        .map_err(|_| RelayError::Rpc)?;
    let xdr = res["entries"][0]["xdr"].as_str().ok_or(RelayError::Rpc)?;
    let bytes = crate::governance_code::decode_base64_bounded(xdr, 64 * 1024)
        .map_err(|_| RelayError::Rpc)?;
    match LedgerEntryData::from_xdr(&bytes, Limits::len(bytes.len()))
        .map_err(|_| RelayError::Rpc)?
    {
        LedgerEntryData::Account(a) => Ok(a.seq_num.0),
        _ => Err(RelayError::Rpc),
    }
}

pub struct Deployment {
    pub contract: String,
    pub tx_hash: String,
    pub ledger: u64,
}

pub struct Submitted {
    /// Address returned by simulation; equals the factory's deterministic
    /// `account_address` for this configuration.
    pub contract: String,
    pub tx_hash: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TxStatus {
    Pending,
    Success { ledger: u64 },
    Failed,
}

/// Status of a relayed transaction, straight from Stellar RPC.
pub async fn transaction_status(state: &AppState, tx_hash: &str) -> Result<TxStatus, RelayError> {
    if !crate::transaction::valid_hash(tx_hash) {
        return Err(RelayError::InvalidInput);
    }
    let res = state
        .rpc_with_params("getTransaction", Some(json!({"hash": tx_hash})))
        .await
        .map_err(|_| RelayError::Rpc)?;
    Ok(match res["status"].as_str() {
        Some("SUCCESS") => TxStatus::Success {
            ledger: res["ledger"].as_u64().unwrap_or(0),
        },
        Some("FAILED") => TxStatus::Failed,
        _ => TxStatus::Pending,
    })
}

/// Simulate, assemble, sign (as fee payer only) and submit a factory
/// `create_account` on Stellar Testnet without waiting for inclusion.
pub async fn submit_account(
    state: &AppState,
    key: &SigningKey,
    factory: &str,
    owner: &SignerKey,
    rp_hash: [u8; 32],
    guardian: Option<&SignerKey>,
) -> Result<Submitted, RelayError> {
    let passphrase = network_passphrase(state).await?;
    let relayer = key.verifying_key().to_bytes();
    let seq = relayer_sequence(state, relayer).await?;
    let tx = create_account_tx(relayer, seq + 1, factory, owner, rp_hash, guardian)
        .ok_or(RelayError::InvalidInput)?;
    let unsigned = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: vec![].try_into().unwrap(),
    });
    let sim = state
        .rpc_with_params(
            "simulateTransaction",
            Some(json!({"transaction": b64(&unsigned.to_xdr(Limits::none()).unwrap())})),
        )
        .await
        .map_err(|_| RelayError::Rpc)?;
    let predicted = sim["results"][0]["xdr"]
        .as_str()
        .and_then(returned_contract)
        .ok_or(RelayError::Simulation)?;
    let ready = assemble(tx, &sim)?;
    let hash = transaction_hash(&ready, &passphrase);
    let envelope = sign(ready, &passphrase, key);
    let sent = state
        .rpc_with_params(
            "sendTransaction",
            Some(json!({"transaction": b64(&envelope.to_xdr(Limits::none()).unwrap())})),
        )
        .await
        .map_err(|_| RelayError::Rpc)?;
    match sent["status"].as_str() {
        Some("PENDING") | Some("DUPLICATE") => Ok(Submitted {
            contract: predicted,
            tx_hash: hash,
        }),
        Some("TRY_AGAIN_LATER") => Err(RelayError::Rpc),
        _ => Err(RelayError::Rejected),
    }
}

/// Submit and wait for confirmation (used by the opt-in live test and CLIs).
pub async fn deploy_account(
    state: &AppState,
    key: &SigningKey,
    factory: &str,
    owner: &SignerKey,
    rp_hash: [u8; 32],
    guardian: Option<&SignerKey>,
) -> Result<Deployment, RelayError> {
    let submitted = submit_account(state, key, factory, owner, rp_hash, guardian).await?;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        match transaction_status(state, &submitted.tx_hash).await? {
            TxStatus::Success { ledger } => {
                return Ok(Deployment {
                    contract: submitted.contract,
                    tx_hash: submitted.tx_hash,
                    ledger,
                })
            }
            TxStatus::Failed => return Err(RelayError::Rejected),
            TxStatus::Pending => {}
        }
    }
    Err(RelayError::Timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    const FACTORY: &str = "CAUJ5FMGDISNYEU7T6EQDYRLFF7CVC5F2PXJVEHQHY7HM275I2X6ITH6";

    fn p256() -> SignerKey {
        let mut k = [7u8; 65];
        k[0] = 4;
        SignerKey::Secp256r1(k)
    }

    #[test]
    fn signer_key_scval_matches_contract_enum_shape() {
        let ScVal::Vec(Some(v)) = p256().to_scval() else {
            panic!()
        };
        assert_eq!(v.len(), 2);
        assert!(matches!(&v[0], ScVal::Symbol(s) if s.0.as_slice() == b"Secp256r1"));
        assert!(matches!(&v[1], ScVal::Bytes(b) if b.len() == 65));
    }

    #[test]
    fn secp256r1_hex_must_be_uncompressed_point() {
        let good = format!("04{}", "11".repeat(64));
        assert!(SignerKey::secp256r1_from_hex(&good).is_some());
        assert!(SignerKey::secp256r1_from_hex(&format!("02{}", "11".repeat(64))).is_none());
        assert!(SignerKey::secp256r1_from_hex(&"04".repeat(33)).is_none());
        assert!(SignerKey::secp256r1_from_hex("zz").is_none());
    }

    #[test]
    fn builds_create_account_invocation() {
        let tx = create_account_tx([1; 32], 42, FACTORY, &p256(), [9; 32], None).unwrap();
        assert_eq!(tx.seq_num.0, 42);
        let OperationBody::InvokeHostFunction(op) = &tx.operations[0].body else {
            panic!()
        };
        let HostFunction::InvokeContract(call) = &op.host_function else {
            panic!()
        };
        assert_eq!(call.function_name.0.as_slice(), b"create_account");
        assert_eq!(call.args.len(), 3);
        assert_eq!(call.args[2], ScVal::Void);
        assert!(op.auth.is_empty());
        assert!(create_account_tx([1; 32], 1, "not-a-contract", &p256(), [0; 32], None).is_none());
    }

    #[test]
    fn assemble_refuses_errors_auth_and_runaway_fees() {
        let tx = || create_account_tx([1; 32], 1, FACTORY, &p256(), [9; 32], None).unwrap();
        let data = SorobanTransactionData {
            ext: stellar_xdr::SorobanTransactionDataExt::V0,
            resources: stellar_xdr::SorobanResources {
                footprint: stellar_xdr::LedgerFootprint {
                    read_only: vec![].try_into().unwrap(),
                    read_write: vec![].try_into().unwrap(),
                },
                instructions: 1,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 1000,
        };
        let data_b64 = b64(&data.to_xdr(Limits::none()).unwrap());
        let ok =
            json!({"transactionData": data_b64, "minResourceFee": "1000", "results":[{"auth":[]}]});
        let assembled = assemble(tx(), &ok).unwrap();
        assert!(assembled.fee > BASE_FEE);
        assert!(matches!(assembled.ext, TransactionExt::V1(_)));
        assert_eq!(
            assemble(tx(), &json!({"error":"boom"})).err(),
            Some(RelayError::Simulation)
        );
        let needs_auth = json!({"transactionData": data_b64, "minResourceFee": "1000", "results":[{"auth":["AAAA"]}]});
        assert_eq!(
            assemble(tx(), &needs_auth).err(),
            Some(RelayError::Rejected)
        );
        let pricey = json!({"transactionData": data_b64, "minResourceFee": "50000000", "results":[{"auth":[]}]});
        assert_eq!(assemble(tx(), &pricey).err(), Some(RelayError::FeeTooHigh));
    }

    #[test]
    fn signature_verifies_over_network_bound_payload() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let tx = create_account_tx(
            key.verifying_key().to_bytes(),
            7,
            FACTORY,
            &p256(),
            [9; 32],
            None,
        )
        .unwrap();
        let hash = transaction_hash(&tx, TESTNET_PASSPHRASE);
        let TransactionEnvelope::Tx(env) = sign(tx.clone(), TESTNET_PASSPHRASE, &key) else {
            panic!()
        };
        let sig =
            ed25519_dalek::Signature::from_slice(env.signatures[0].signature.0.as_slice()).unwrap();
        let digest = hex::decode(&hash).unwrap();
        assert!(key.verifying_key().verify(&digest, &sig).is_ok());
        // A different network yields a different payload.
        assert_ne!(
            hash,
            transaction_hash(&tx, "Public Global Stellar Network ; September 2015")
        );
    }

    #[test]
    fn decodes_returned_contract_address() {
        let v = ScVal::Address(ScAddress::Contract(ContractId(Hash([3; 32]))));
        let s = returned_contract(&b64(&v.to_xdr(Limits::none()).unwrap())).unwrap();
        assert!(s.starts_with('C') && s.len() == 56);
        assert!(returned_contract(&b64(&ScVal::Void.to_xdr(Limits::none()).unwrap())).is_none());
    }

    #[test]
    fn relayer_secret_parses_from_strkey() {
        let seed =
            stellar_strkey::Unredacted(&stellar_strkey::ed25519::PrivateKey([8; 32])).to_string();
        assert!(relayer_key(seed.as_str()).is_some());
        assert!(relayer_key("SNOTAKEY").is_none());
    }
}
