//! Public Soroban contract-instance discovery; does not attest a smart wallet.
use serde_json::{json,Value};

pub fn instance_ledger_key(address:&str)->Option<String>{
 if !crate::ledger_events::valid_contract_id(address){return None;}
 let mut decoded=[0u8;35];
 let(mut acc,mut bits,mut pos)=(0_u32,0_u32,0_usize);
 for b in address.bytes(){
  let v=match b {b'A'..=b'Z'=>u32::from(b-b'A'),b'2'..=b'7'=>u32::from(b-b'2'+26),_=>return None};
  acc=(acc<<5)|v;bits+=5;
  if bits>=8 {
   bits-=8;
   if pos>=35{return None;}
   decoded[pos]=((acc>>bits)&255) as u8;
   pos+=1;acc&=(1<<bits)-1;
  }
 }
 if pos!=35||bits!=0||decoded[0]!=16{return None;}
 let mut key=Vec::with_capacity(48);
 key.extend_from_slice(&6u32.to_be_bytes());
 key.extend_from_slice(&1u32.to_be_bytes());
 key.extend_from_slice(&decoded[1..33]);
 key.extend_from_slice(&20u32.to_be_bytes());
 key.extend_from_slice(&1u32.to_be_bytes());
 Some(encode_base64(&key))
}
fn encode_base64(bytes:&[u8])->String{
 const ALPHABET:&[u8]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 let mut out=String::new();
 for chunk in bytes.chunks(3){
  let a=chunk[0];let b=*chunk.get(1).unwrap_or(&0);let c=*chunk.get(2).unwrap_or(&0);
  out.push(ALPHABET[(a>>2)as usize]as char);
  out.push(ALPHABET[(((a&3)<<4)|(b>>4))as usize]as char);
  out.push(if chunk.len()>1{ALPHABET[(((b&15)<<2)|(c>>6))as usize]as char}else{'='});
  out.push(if chunk.len()>2{ALPHABET[(c&63)as usize]as char}else{'='});
 }
 out
}
#[derive(Debug)]
pub struct InspectError;
pub fn inspect_entry(reply:&Value,network_head:u64,key:&str)->Result<Option<Value>,InspectError>{
 let ledger=reply["latestLedger"].as_u64().ok_or(InspectError)?;
 if ledger==0||ledger.abs_diff(network_head)>15{return Err(InspectError);}
 let entries=reply["entries"].as_array().ok_or(InspectError)?;
 if entries.is_empty(){return Ok(None);}
 if entries.len()!=1||entries[0]["key"]!=key{return Err(InspectError);}
 let item=&entries[0];
 let last=item["lastModifiedLedgerSeq"].as_u64().ok_or(InspectError)?;
 let expiry=item["liveUntilLedgerSeq"].as_u64().ok_or(InspectError)?;
 if last==0||last>ledger||expiry<ledger{return Err(InspectError);}
 let hash=crate::governance_code::executable_hash(item["xdr"].as_str().ok_or(InspectError)?,key).map_err(|_|InspectError)?;
 Ok(Some(json!({"observed_ledger_sequence":ledger,
  "executable_wasm_hash":hash,"live_until_ledger":expiry})))
}
#[cfg(test)]
mod tests{
 use super::*;
 #[test]fn reconstructs_c_address_instance_key(){
  assert_eq!(instance_ledger_key("CDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW7JOB").as_deref(),
   Some("AAAABgAAAAHl44SewmWZxNusdHWJp7JyxQebCspSHIfef+tcBeeXbwAAABQAAAAB"));
  assert!(instance_ledger_key("").is_none());
  assert!(instance_ledger_key("CAAAAA").is_none());
 }
 #[test]fn rejects_missing_ledger_metadata(){
  assert!(inspect_entry(&json!({"latestLedger":5,"entries":[{"key":"wrong"}]}),5,"target").is_err());
  assert!(inspect_entry(&json!({"latestLedger":5,"entries":[]}),5,"target").unwrap().is_none());
  assert!(inspect_entry(&json!({"latestLedger":5,"entries":[]}),35,"target").is_err());
 }
 #[test]fn accepts_a_live_contract_only_with_matching_key_hash_and_ttl(){
  let address="CDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW7JOB";
  let key=instance_ledger_key(address).unwrap();
  let raw_key=crate::governance_code::decode_base64(&key).unwrap();
  let mut entry=Vec::<u8>::new();
  entry.extend_from_slice(&6u32.to_be_bytes()); // LedgerEntryData.ContractData
  entry.extend_from_slice(&0u32.to_be_bytes()); // ContractDataEntry.ext
  entry.extend_from_slice(&1u32.to_be_bytes()); // SCAddress.Contract
  entry.extend_from_slice(&raw_key[8..40]);
  entry.extend_from_slice(&20u32.to_be_bytes()); // instance key
  entry.extend_from_slice(&1u32.to_be_bytes()); // persistent
  entry.extend_from_slice(&19u32.to_be_bytes()); // ContractInstance SCVal
  entry.extend_from_slice(&0u32.to_be_bytes()); // Wasm executable tag
  entry.extend_from_slice(&[42u8;32]); // executable hash
  entry.extend_from_slice(&0u32.to_be_bytes()); // absent storage map
  assert_eq!(entry.len(),96);
  let xdr=encode_base64(&entry);
  let response=json!({"latestLedger":500,"entries":[{
    "key":key,"xdr":xdr,"lastModifiedLedgerSeq":495,"liveUntilLedgerSeq":550
  }]});
  let valid=inspect_entry(&response,500,&key).unwrap().unwrap();
  assert_eq!(valid["executable_wasm_hash"],"2a".repeat(32));
  assert_eq!(valid["live_until_ledger"],550);
  let mut expired=response.clone();
  expired["entries"][0]["liveUntilLedgerSeq"]=json!(499);
  assert!(inspect_entry(&expired,500,&key).is_err());
  let mut wrong_key=response.clone();
  wrong_key["entries"][0]["key"]=json!("forged");
  assert!(inspect_entry(&wrong_key,500,&key).is_err());
  let mut repeated=response.clone();
  repeated["entries"].as_array_mut().unwrap().push(response["entries"][0].clone());
  assert!(inspect_entry(&repeated,500,&key).is_err());
 }

}
