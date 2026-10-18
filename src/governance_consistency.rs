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
