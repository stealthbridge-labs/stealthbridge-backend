//! Cross-endpoint public evidence consistency. Never authorizes execution.
use serde_json::Value;

/// A successful return means *only* that read-only observations agree.
/// Signed release trust, live RPC transport authenticity, privacy and asset
/// execution are separate concerns.
pub fn consistent_public_governance(
 release:&Value, code:&Value, admin:&Value,
)->bool{
 if release["network"]!="testnet"||code["network"]!="testnet"||admin["network"]!="testnet"
  ||release["payment_execution_enabled"]!=false||code["payment_execution_enabled"]!=false
  ||admin["payment_execution_enabled"]!=false||release["fee_collection_enabled"]!=false
  ||code["fee_collection_enabled"]!=false||admin["fee_collection_enabled"]!=false
  ||release["privacy_verified"]!=false||code["privacy_verified"]!=false
  ||admin["privacy_verified"]!=false
  ||release["deployment_transactions_confirmed"]!=true
  ||code["all_executable_hashes_match_release"]!=true
  ||admin["all_administrators_match_deployment"]!=true
  ||admin["same_administrator_for_all_contracts"]!=true
  ||admin["administrator_entries_read_from_current_storage"]!=true
  {return false;}
 let ledger=release["observed_ledger_sequence"].as_u64();
 if ledger.is_none()||ledger!=code["observed_ledger_sequence"].as_u64()
  ||ledger!=admin["observed_ledger_sequence"].as_u64(){return false;}
 let (Some(rs),Some(cs),Some(as_))=(
  release["contracts"].as_array(),code["contracts"].as_array(),admin["contracts"].as_array()
 )else{return false;};
 if rs.len()!=3||cs.len()!=3||as_.len()!=3{return false;}
 for i in 0..3{
  let (r,c,a)=(&rs[i],&cs[i],&as_[i]);
  if r["name"]!=c["name"]||r["name"]!=a["name"]
   ||r["contract_id"]!=c["contract_id"]||r["contract_id"]!=a["contract_id"]
   ||r["wasm_sha256_at_release"]!=c["release_executable_wasm_hash"]
   ||c["matches_reviewed_release"]!=true
   ||a["matches_deployment_administrator"]!=true
   ||a["pending_administrator"]!=Value::Null||a["paused"]==true {return false;}
 }
 true
}
#[cfg(test)]
mod tests{
 use super::*;
 use serde_json::json;
 #[test]fn requires_matching_identity_hash_and_safe_administrator_at_same_ledger(){
  let contract=|name:&str,id:&str,hash:&str|json!({
   "name":name,"contract_id":id,"wasm_sha256_at_release":hash
  });
  let release=json!({
   "network":"testnet","payment_execution_enabled":false,"privacy_verified":false,
   "fee_collection_enabled":false,"deployment_transactions_confirmed":true,
   "observed_ledger_sequence":5244400,
   "contracts":[contract("corridor-registry","C1","h1"),
    contract("policy-registry","C2","h2"),
    contract("governance-gate","C3","h3")]
  });
  let code=json!({
   "network":"testnet","payment_execution_enabled":false,"privacy_verified":false,
   "fee_collection_enabled":false,"all_executable_hashes_match_release":true,
   "observed_ledger_sequence":5244400,
   "contracts":[
    {"name":"corridor-registry","contract_id":"C1","release_executable_wasm_hash":"h1","matches_reviewed_release":true},
    {"name":"policy-registry","contract_id":"C2","release_executable_wasm_hash":"h2","matches_reviewed_release":true},
    {"name":"governance-gate","contract_id":"C3","release_executable_wasm_hash":"h3","matches_reviewed_release":true}
   ]
  });
  let admin=json!({
   "network":"testnet","payment_execution_enabled":false,"privacy_verified":false,
   "fee_collection_enabled":false,"all_administrators_match_deployment":true,
   "same_administrator_for_all_contracts":true,
   "administrator_entries_read_from_current_storage":true,
   "observed_ledger_sequence":5244400,
   "contracts":[
    {"name":"corridor-registry","contract_id":"C1","matches_deployment_administrator":true,"pending_administrator":null,"paused":false},
    {"name":"policy-registry","contract_id":"C2","matches_deployment_administrator":true,"pending_administrator":null,"paused":false},
    {"name":"governance-gate","contract_id":"C3","matches_deployment_administrator":true,"pending_administrator":null,"paused":null}
   ]
  });
  assert!(consistent_public_governance(&release,&code,&admin));
  let mut v=code.clone();v["contracts"][1]["release_executable_wasm_hash"]=json!("forged");
  assert!(!consistent_public_governance(&release,&v,&admin));
  v=code.clone();v["observed_ledger_sequence"]=json!(5244401);
  assert!(!consistent_public_governance(&release,&v,&admin));
  let mut a=admin.clone();a["contracts"][0]["pending_administrator"]=json!("Gnominee");
  assert!(!consistent_public_governance(&release,&code,&a));
  a=admin.clone();a["contracts"][1]["paused"]=json!(true);
  assert!(!consistent_public_governance(&release,&code,&a));
  a=admin.clone();a["contracts"][2]["contract_id"]=json!("wrong");
  assert!(!consistent_public_governance(&release,&code,&a));
 }
 #[test]fn fails_closed_when_missing_or_claims_payment(){
  assert!(!consistent_public_governance(&json!({}),&json!({}),&json!({})));
  let invalid=json!({"network":"testnet","payment_execution_enabled":true});
  assert!(!consistent_public_governance(&invalid,&invalid,&invalid));
 }
 #[test]fn denies_inconsistent_ledger(){
  let release=json!({"network":"testnet","payment_execution_enabled":false,
   "fee_collection_enabled":false,"privacy_verified":false,
   "deployment_transactions_confirmed":true,"observed_ledger_sequence":5});
  let code=json!({"network":"testnet","payment_execution_enabled":false,
   "fee_collection_enabled":false,"privacy_verified":false,
   "all_executable_hashes_match_release":true,"observed_ledger_sequence":6});
  let admin=json!({"network":"testnet","payment_execution_enabled":false,
   "fee_collection_enabled":false,"privacy_verified":false,
   "all_administrators_match_deployment":true,"same_administrator_for_all_contracts":true,
   "administrator_entries_read_from_current_storage":true,"observed_ledger_sequence":5});
  assert!(!consistent_public_governance(&release,&code,&admin));
 }
}
