//! Public Testnet governance release reconciliation. No signing or transfers.
use reqwest::Client;
use serde_json::{json,Value};
use crate::wallet;
const EVIDENCE:&str=include_str!("../deployments/testnet/governance-deployment-evidence.v2.json");
const ADMIN:&str="GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
const FIXED:[(&str,&str,&str);3]=[
 ("corridor-registry","CDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW7JOB","588d17f99850272f2f18e6ee407d94329b4f8ae415c2f6b71993cf59f4139099"),
 ("policy-registry","CBXWEA5PMDTBN5AN7FJYGGAPIWLRKXYHWLVWG5WOXH3HSRDB4RYTJBN5","856186ba3dca1feff010c670bd1ae9818bf69e284304273f943745603b9a7912"),
 ("governance-gate","CD2KIMDRYJMKGO5SMIBOQP6ADPW5I4THNZFGXWYLIPGSXAI5NRXVAPKV","66b40fe5ee4f704a91acf39922ed130cc1eb4fc0cdc3c5ee5a30614921f4aa81")
];
fn hex(s:&str)->bool{s.len()==64 && s.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase())}
fn validate(value:&Value)->Result<(),()>{
 if value["schemaVersion"]!=2||value["network"]!="testnet"||
   value["recordType"]!="soroban-testnet-governance-deployment-observation"||
   value["networkPassphrase"]!="Test SDF Network ; September 2015"||
   value["sourceCommit"]!="130c577ef6f44412a249d43e3e459cedecb5c970"||
   value["administrator"]!=ADMIN||value["deployer"]!=ADMIN||
   wallet::decode_account_address(ADMIN).is_none()||
   value["scope"]["governanceDeployed"]!=true||
   value["scope"]["privacyVerified"]!=false||
   value["scope"]["paymentExecutionEnabled"]!=false||
   value["scope"]["platformFeesEnabled"]!=false||
   value["scope"]["fiatPayoutEnabled"]!=false||
   value["verification"]["onchainWasmReadbackChecked"]!=true||
   value["verification"]["onchainConstructorStateReadbackChecked"]!=true||
   value["verification"]["independentExternalAuditCompleted"]!=false{return Err(());}
 let contracts=value["contracts"].as_object().ok_or(())?;
 if contracts.len()!=3{return Err(());}
 for (name,id,hash) in FIXED{
  let c=contracts.get(name).ok_or(())?;
  if c["contractId"]!=id||c["wasmSha256"]!=hash||
     c["observedAdmin"]!=ADMIN||c["readbackWasmMatches"]!=true||
     !c["deploymentTx"].as_str().is_some_and(hex)||
     !c["wasmUploadTx"].as_str().is_some_and(hex)||
     !c["abiSha256"].as_str().is_some_and(hex)||
     c["deploymentLedger"].as_u64().is_none_or(|n|n==0){return Err(());}
  if name!="governance-gate"&&c["observedPaused"]!=false{return Err(());}
 }
 if contracts["governance-gate"]["observedCorridorRegistry"]!=FIXED[0].1||
    contracts["governance-gate"]["observedPolicyRegistry"]!=FIXED[1].1{return Err(());}
 Ok(())
}
async fn check_receipt(http:&Client,tx:&str,ledger:u64)->Result<(),()>{
 if !hex(tx){return Err(());}
 let mut res=http.get(format!("https://horizon-testnet.stellar.org/transactions/{tx}"))
     .header("accept","application/json").send().await.map_err(|_|())?;
 if !res.status().is_success()||res.content_length().is_some_and(|n|n>16384){return Err(());}
 let mut b=Vec::new();
 while let Some(chunk)=res.chunk().await.map_err(|_|())?{
  if chunk.len()>16384-b.len(){return Err(());}
  b.extend_from_slice(&chunk);
 }
 let v:Value=serde_json::from_slice(&b).map_err(|_|())?;
 if v["hash"]!=tx||v["successful"]!=true||v["ledger"].as_u64()!=Some(ledger){return Err(());}
 Ok(())
}
#[derive(Debug)]
pub struct GovernanceReleaseUnavailable;
impl From<()> for GovernanceReleaseUnavailable {
 fn from(_:())->Self { Self }
}
pub async fn observe(http:&Client,network_ledger:u64,closed_at:&str)->Result<Value,GovernanceReleaseUnavailable>{
 let v:Value=serde_json::from_str(EVIDENCE).map_err(|_|())?;
 validate(&v)?;
 let c=&v["contracts"]["corridor-registry"];
 let p=&v["contracts"]["policy-registry"];
 let g=&v["contracts"]["governance-gate"];
 let (a,b,d)=tokio::join!(
  check_receipt(http,c["deploymentTx"].as_str().ok_or(())?,c["deploymentLedger"].as_u64().ok_or(())?),
  check_receipt(http,p["deploymentTx"].as_str().ok_or(())?,p["deploymentLedger"].as_u64().ok_or(())?),
  check_receipt(http,g["deploymentTx"].as_str().ok_or(())?,g["deploymentLedger"].as_u64().ok_or(())?)
 );
 a?;b?;d?;
 let contracts:Vec<Value>=FIXED.iter().map(|(name,_,_)|{
  let r=&v["contracts"][*name];
  json!({"name":name,"contract_id":r["contractId"],
    "wasm_sha256_at_release":r["wasmSha256"],"deployment_tx":r["deploymentTx"],
    "deployment_ledger":r["deploymentLedger"],"deployment_transaction_confirmed":true})
 }).collect();
 Ok(json!({"schema_version":1,"network":"testnet",
  "source":"stealthbridge-contracts/deployments/testnet/governance-deployment-evidence.v2.json",
  "release_date":"2026-10-17","administrator_at_release":ADMIN,
  "observed_ledger_sequence":network_ledger,"observed_ledger_closed_at_unix":closed_at,
  "contracts":contracts,"deployment_transactions_confirmed":true,
  "onchain_code_freshly_verified":false,"administrator_freshly_verified":false,
  "privacy_verified":false,"payment_execution_enabled":false,"fee_collection_enabled":false}))
}
#[cfg(test)]
mod tests{
 use super::*;
 #[test]fn pinned_release_is_consistent(){let v:Value=serde_json::from_str(EVIDENCE).unwrap();validate(&v).unwrap();}
 #[test]fn corrupt_contract_or_false_payment_claims_are_rejected(){
  let mut v:Value=serde_json::from_str(EVIDENCE).unwrap();
  v["scope"]["paymentExecutionEnabled"]=json!(true);assert!(validate(&v).is_err());
  v=serde_json::from_str(EVIDENCE).unwrap();
  v["contracts"]["governance-gate"]["observedCorridorRegistry"]=json!("WRONG");
  assert!(validate(&v).is_err());
  v=serde_json::from_str(EVIDENCE).unwrap();
  v["contracts"]["policy-registry"]["wasmSha256"]=json!("0".repeat(64));
  assert!(validate(&v).is_err());
 }
}
