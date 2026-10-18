//! Read-only current Soroban contract INSTANCE executable hash observation.
//! Parses the fixed XDR prefix only: NOT a complete instance-storage decoder,
//! current admin attestation, source audit, privacy gate or fund movement.
use serde_json::{json,Value};
const EXPECTED:[(&str,&str,&str,&str);3]=[
 ("corridor-registry","CDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW7JOB",
  "AAAABgAAAAHl44SewmWZxNusdHWJp7JyxQebCspSHIfef+tcBeeXbwAAABQAAAAB",
  "588d17f99850272f2f18e6ee407d94329b4f8ae415c2f6b71993cf59f4139099"),
 ("policy-registry","CBXWEA5PMDTBN5AN7FJYGGAPIWLRKXYHWLVWG5WOXH3HSRDB4RYTJBN5",
  "AAAABgAAAAFvYgOvYOYW9A35U4MYD0WXFV8Hsutjds659nlEYeRxNAAAABQAAAAB",
  "856186ba3dca1feff010c670bd1ae9818bf69e284304273f943745603b9a7912"),
 ("governance-gate","CD2KIMDRYJMKGO5SMIBOQP6ADPW5I4THNZFGXWYLIPGSXAI5NRXVAPKV",
  "AAAABgAAAAH0pDBxwlijO7JiAug/wBvt1HJnbkpr2wtDzSuBHWxvUAAAABQAAAAB",
  "66b40fe5ee4f704a91acf39922ed130cc1eb4fc0cdc3c5ee5a30614921f4aa81")
];
pub fn ledger_keys()->Vec<&'static str>{EXPECTED.iter().map(|item|item.2).collect()}
fn digit(b:u8)->Option<u8>{
 match b{b'A'..=b'Z'=>Some(b-b'A'),b'a'..=b'z'=>Some(b-b'a'+26),
 b'0'..=b'9'=>Some(b-b'0'+52),b'+'=>Some(62),b'/'=>Some(63),_=>None}
}
fn decode_base64(s:&str)->Result<Vec<u8>,()>{
 let b=s.as_bytes();
 if b.is_empty()||b.len()>65_536||!b.len().is_multiple_of(4){return Err(());}
 let mut out=Vec::with_capacity(b.len()/4*3);
 for (i,block) in b.as_chunks::<4>().0.iter().enumerate(){
  let last=i+1==b.len()/4;
  let padding=usize::from(block[3]==b'=')+usize::from(block[2]==b'=');
  if (padding!=0&&!last)||padding>2|| (block[2]==b'='&&block[3]!=b'='){return Err(());}
  let p=digit(block[0]).ok_or(())?;
  let q=digit(block[1]).ok_or(())?;
  let r=if block[2]==b'='{0}else{digit(block[2]).ok_or(())?};
  let t=if block[3]==b'='{0}else{digit(block[3]).ok_or(())?};
  if (padding==1 && (r&3)!=0)||(padding==2&&(q&15)!=0){return Err(());}
  out.push((p<<2)|(q>>4));
  if padding<2 {out.push((q<<4)|(r>>2));}
  if padding==0 {out.push((r<<6)|t);}
 }
 Ok(out)
}
fn u32_at(v:&[u8],i:usize)->Result<u32,()>{
 let s=v.get(i..i+4).ok_or(())?;
 Ok(u32::from_be_bytes([s[0],s[1],s[2],s[3]]))
}
fn hex32(bytes:&[u8])->Result<String,()>{
 if bytes.len()!=32{return Err(());}
 let mut s=String::with_capacity(64);
 for b in bytes{use std::fmt::Write as _;write!(s,"{b:02x}").map_err(|_|())?;}
 Ok(s)
}
/// Exactly decode the contract-instance XDR *header* through executable hash.
/// Never assume the rest of instance storage is verified or claim WASM bytes were fetched.
/// Actual LedgerEntryData.ContractData (6), SCAddress.Contract (1)+Hash,
/// SCVal.LedgerKeyContractInstance (20), durability Persistent (1),
/// SCVal.ContractInstance (19), ContractExecutable.Wasm (0)+Hash,
/// SCMap* (0 or 1). There is NO ContractDataEntry ExtensionPoint.
fn executable_hash(value:&str,expected_ledger_key:&str)->Result<String,()>{
 let data=decode_base64(value)?;
 let ledger_key=decode_base64(expected_ledger_key)?;
 if ledger_key.len()!=48||data.len()<92||data.len()>48_000{return Err(());}
 for (offset,tag) in [(0,6),(4,1),(40,20),(44,1),(48,19),(52,0)]{
  if u32_at(&data,offset)?!=tag{return Err(());}
 }
 if data.get(8..40)!=ledger_key.get(8..40){return Err(());}
 if u32_at(&data,88)?>1{return Err(());}
 hex32(data.get(56..88).ok_or(())?)
}
/// Public RPC supports sparse results for expired/absent ledger entries.
/// Require all three and an observed ledger consistent with a fresh Testnet network
/// head; fail closed on any missing/malformed/repeated/wrong-key instance.
#[derive(Debug)]
pub struct CodeObservationUnavailable;
impl From<()> for CodeObservationUnavailable {fn from(_:())->Self{Self}}
pub fn assess(reply:&Value,expected_network_ledger:u64)->Result<Value,CodeObservationUnavailable>{
 let ledger=reply["latestLedger"].as_u64().ok_or(())?;
 if ledger==0||ledger.abs_diff(expected_network_ledger)>15{return Err(CodeObservationUnavailable);}
 let entries=reply["entries"].as_array().ok_or(())?;
 if entries.len()!=3{return Err(CodeObservationUnavailable);}
 let mut results=Vec::new();
 let mut all=true;
 for (name,id,key,release_hash) in EXPECTED{
  let matches:Vec<&Value>=entries.iter().filter(|v|v["key"]==key).collect();
  if matches.len()!=1{return Err(CodeObservationUnavailable);}
  let e=matches[0];
  let last=e["lastModifiedLedgerSeq"].as_u64().ok_or(())?;
  let expires=e["liveUntilLedgerSeq"].as_u64().ok_or(())?;
  if last==0||last>ledger||expires<ledger{return Err(CodeObservationUnavailable);}
  let current=executable_hash(e["xdr"].as_str().ok_or(())?,key)?;
  let unchanged=current==release_hash;
  all&=unchanged;
  results.push(json!({"name":name,"contract_id":id,
   "current_executable_wasm_hash":current,"release_executable_wasm_hash":release_hash,
   "matches_reviewed_release":unchanged,
   "last_modified_ledger":last,"live_until_ledger":expires}));
 }
 Ok(json!({"schema_version":1,"network":"testnet","source":"stellar-rpc/getLedgerEntries",
  "observed_ledger_sequence":ledger,"contracts":results,
  "all_executable_hashes_match_release":all,
  "current_administrator_verified":false,"wasm_bytes_freshly_downloaded":false,
  "privacy_verified":false,"payment_execution_enabled":false,"fee_collection_enabled":false}))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn base64(v:&[u8])->String{
  const ABC:&[u8]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let mut o=String::new();
  for b in v.chunks(3){
   let a=b[0];let c=*b.get(1).unwrap_or(&0);let d=*b.get(2).unwrap_or(&0);
   o.push(ABC[(a>>2)as usize] as char);
   o.push(ABC[(((a&3)<<4)|(c>>4))as usize] as char);
   o.push(if b.len()>1{ABC[(((c&15)<<2)|(d>>6))as usize] as char}else{'='});
   o.push(if b.len()>2{ABC[(d&63)as usize] as char}else{'='});
  }
  o
 }
 fn data(key:&str,hash:&str)->String{
  let k=decode_base64(key).unwrap();
  let mut o=Vec::new();
  o.extend_from_slice(&6u32.to_be_bytes());
  o.extend_from_slice(&1u32.to_be_bytes());o.extend_from_slice(&k[8..40]);
  for tag in [20u32,1,19,0]{o.extend_from_slice(&tag.to_be_bytes());}
  for i in (0..64).step_by(2){o.push(u8::from_str_radix(&hash[i..i+2],16).unwrap());}
  o.extend_from_slice(&0u32.to_be_bytes());
  base64(&o)
 }
 fn reply()->Value{
  json!({"latestLedger":5244400,"entries":EXPECTED.iter().map(|(_,_,key,hash)|json!({
   "key":key,"xdr":data(key,hash),"lastModifiedLedgerSeq":5244293,
   "liveUntilLedgerSeq":5244402})).collect::<Vec<_>>()})
 }
 #[test]fn exact_pinned_instance_keys_are_contract_data_persistent(){
  for (_,_,key,_) in EXPECTED{
   let k=decode_base64(key).unwrap();assert_eq!(k.len(),48);
   assert_eq!(u32_at(&k,0),Ok(6));assert_eq!(u32_at(&k,4),Ok(1));
   assert_eq!(u32_at(&k,40),Ok(20));assert_eq!(u32_at(&k,44),Ok(1));
  }
 }
 #[test]fn xdr_hash_observation_matches_exact_release(){
  let v=reply();let result=assess(&v,5244397).unwrap();
  assert_eq!(result["all_executable_hashes_match_release"],true);
  assert_eq!(result["payment_execution_enabled"],false);
  assert_eq!(result["current_administrator_verified"],false);
 }
 #[test]fn code_drift_is_visible_not_falsely_approved(){
  let mut v=reply();v["entries"][1]["xdr"]=json!(data(EXPECTED[1].2,&"a".repeat(64)));
  let r=assess(&v,5244400).unwrap();
  assert_eq!(r["all_executable_hashes_match_release"],false);
  assert_eq!(r["contracts"][1]["matches_reviewed_release"],false);
 }
 #[test]fn real_contract_data_xdr_has_no_extension_discriminator(){
  let (_,_,key,hash)=EXPECTED[0];
  let bytes=decode_base64(&data(key,hash)).unwrap();
  assert_eq!(bytes.len(),92);
  assert_eq!(u32_at(&bytes,0),Ok(6));
  assert_eq!(u32_at(&bytes,4),Ok(1)); // SCAddress.Contract, not an ExtensionPoint!
  assert_eq!(u32_at(&bytes,40),Ok(20));
  assert_eq!(u32_at(&bytes,48),Ok(19));
  assert_eq!(u32_at(&bytes,52),Ok(0));
  assert_eq!(u32_at(&bytes,88),Ok(0)); // Empty SCMap*
  let mut forged=bytes.clone();forged[4..8].copy_from_slice(&0u32.to_be_bytes());
  assert!(executable_hash(&base64(&forged),key).is_err());
 }
 #[test]fn malformed_rpc_missing_ttl_stale_ledger_and_wrong_contract_are_rejected(){
  let v=reply();
  assert!(assess(&v,5244000).is_err());
  let mut x=v.clone();x["entries"].as_array_mut().unwrap().pop();assert!(assess(&x,5244400).is_err());
  x=v.clone();x["entries"][0]["liveUntilLedgerSeq"]=json!(5244399);assert!(assess(&x,5244400).is_err());
  x=v.clone();x["entries"][0]["key"]=json!("WRONG");assert!(assess(&x,5244400).is_err());
  x=v.clone();x["entries"][0]["xdr"]=json!("AAAA");assert!(assess(&x,5244400).is_err());
  x=v.clone();x["entries"][0]["xdr"]=json!(data(EXPECTED[1].2,EXPECTED[0].3));assert!(assess(&x,5244400).is_err());
  for bad in ["A?==","A===","AAAA===","AR==","ab+="]{
   assert!(decode_base64(bad).is_err(),"rejected invalid base64 {bad}");
  }
 }
}
