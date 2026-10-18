//! Strict, read-only Testnet administrator observations from Soroban INSTANCE
//! SCMap XDR. Do NOT confuse stored public admin with signing authorization,
//! control of secure-store keys, audited payment rails, or upgrade approval.
use serde_json::{json,Value};
use crate::governance_code;

const ADMIN_RELEASE:&str="GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
const CID:[(&str,&str);3]=[
 ("corridor-registry","CDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW7JOB"),
 ("policy-registry","CBXWEA5PMDTBN5AN7FJYGGAPIWLRKXYHWLVWG5WOXH3HSRDB4RYTJBN5"),
 ("governance-gate","CD2KIMDRYJMKGO5SMIBOQP6ADPW5I4THNZFGXWYLIPGSXAI5NRXVAPKV"),
];
#[derive(Debug)]
pub struct AdminObservationUnavailable;
impl From<()> for AdminObservationUnavailable {fn from(_:())->Self{Self}}

#[derive(Clone,Debug,PartialEq,Eq)]
enum ScVal {
    Account([u8;32]),Contract([u8;32]),Symbol(String),
    Vec(Vec<ScVal>),Map(Vec<(ScVal,ScVal)>),Bool(bool),Other,
}
struct Decoder<'a>{data:&'a [u8],pos:usize,nodes:u32}
impl<'a> Decoder<'a>{
 fn new(data:&'a [u8])->Self{Self{data,pos:0,nodes:0}}
 fn read(&mut self,size:usize)->Result<&'a [u8],()>{
  let finish=self.pos.checked_add(size).ok_or(())?;
  let v=self.data.get(self.pos..finish).ok_or(())?;
  self.pos=finish;Ok(v)
 }
 fn u32(&mut self)->Result<u32,()>{
  let b=self.read(4)?;
  Ok(u32::from_be_bytes([b[0],b[1],b[2],b[3]]))
 }
 fn bytes<const N:usize>(&mut self)->Result<[u8;N],()>{
  let mut b=[0u8;N];b.copy_from_slice(self.read(N)?);Ok(b)
 }
 fn sized(&mut self, limit:usize)->Result<&'a [u8],()>{
  let n=self.u32()? as usize;
  if n>limit{return Err(());}
  let b=self.read(n)?;
  let pad=(4-n%4)%4;
  if self.read(pad)?.iter().any(|v|*v!=0){return Err(());}
  Ok(b)
 }
 fn list_length(&mut self)->Result<usize,()>{
  let flag=self.u32()?;
  if flag!=1{return Err(());} // No null Vec/Map inside expected instance storage.
  let n=self.u32()? as usize;
  if n>64{return Err(());}
  Ok(n)
 }
 fn val(&mut self,depth:u8)->Result<ScVal,()>{
  self.nodes+=1;
  if depth>8||self.nodes>256{return Err(());}
  match self.u32()?{
   0=>match self.u32()?{0=>Ok(ScVal::Bool(false)),1=>Ok(ScVal::Bool(true)),_=>Err(())},
   1=>Ok(ScVal::Other),
   2=>{self.read(8)?;Ok(ScVal::Other)}, // SCError type + code
   3|4=>{self.read(4)?;Ok(ScVal::Other)},
   5..=8=>{self.read(8)?;Ok(ScVal::Other)},
   9|10=>{self.read(16)?;Ok(ScVal::Other)},
   11|12=>{self.read(32)?;Ok(ScVal::Other)},
   13|14=>{self.sized(8192)?;Ok(ScVal::Other)},
   15=>{
    let b=self.sized(32)?;
    if b.is_empty()||!b.iter().all(|c|c.is_ascii_alphanumeric()||*c==b'_'){return Err(());}
    Ok(ScVal::Symbol(std::str::from_utf8(b).map_err(|_|())?.to_owned()))
   },
   16=>{
    let n=self.list_length()?;
    let mut v=Vec::with_capacity(n);
    for _ in 0..n{v.push(self.val(depth+1)?);}
    Ok(ScVal::Vec(v))
   },
   17=>{
    let n=self.list_length()?;
    let mut v=Vec::with_capacity(n);
    for _ in 0..n{v.push((self.val(depth+1)?,self.val(depth+1)?));}
    Ok(ScVal::Map(v))
   },
   18=>match self.u32()?{
     0=>{if self.u32()?!=0{return Err(());}Ok(ScVal::Account(self.bytes()?))},
     1=>Ok(ScVal::Contract(self.bytes()?)),
     _=>Err(()),
   },
   _=>Err(()), // No nested contract instance, nonce or unfamiliar SCVal accepted.
  }
 }
}

fn strkey(tag:u8,key:[u8;32])->String{
 let mut raw=[0u8;35];
 raw[0]=tag;raw[1..33].copy_from_slice(&key);
 let mut crc=0u16;
 for b in &raw[..33]{
  crc^=u16::from(*b)<<8;
  for _ in 0..8{crc=if (crc&0x8000)!=0{(crc<<1)^0x1021}else{crc<<1};}
 }
 raw[33..35].copy_from_slice(&crc.to_le_bytes());
 let abc=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
 let mut answer=String::with_capacity(56);
 let mut acc=0u32;let mut bits=0u32;
 for b in raw{
  acc=(acc<<8)|u32::from(b);bits+=8;
  while bits>=5{bits-=5;answer.push(abc[((acc>>bits)&31)as usize] as char);acc&=(1<<bits)-1;}
 }
 answer
}
fn public_account(value:&ScVal)->Result<String,()>{
 match value{ScVal::Account(k)=>Ok(strkey(6<<3,*k)),_=>Err(())}
}
fn public_contract(value:&ScVal)->Result<String,()>{
 match value{ScVal::Contract(k)=>Ok(strkey(2<<3,*k)),_=>Err(())}
}

/// This parser checks *every* stored map entry and refuses duplicates and
/// malformed XDR. It does not publish unrelated stored values.
fn parse_instance(xdr:&str,expected_key:&str)->Result<Vec<(String,ScVal)>,()>{
 let raw=governance_code::decode_base64(xdr)?;
 let ledger_key=governance_code::decode_base64(expected_key)?;
 if ledger_key.len()!=48||raw.len()<96||raw.len()>48_000{return Err(());}
 let mut d=Decoder::new(&raw);
 if d.u32()!=Ok(6)||d.u32()!=Ok(1){return Err(());}
 if d.read(32)?!=ledger_key.get(8..40).ok_or(())?{return Err(());}
 if d.u32()!=Ok(20)||d.u32()!=Ok(1)||d.u32()!=Ok(19)||d.u32()!=Ok(0){
  return Err(());
 }
 d.read(32)?; // Executable hash, validated independently by governance_code::assess
 if d.u32()!=Ok(1){return Err(());} // Require actual, not absent, instance storage.
 let count=d.u32()? as usize;
 if count<2||count>32{return Err(());}
 let mut fields=Vec::with_capacity(count);
 for _ in 0..count{
  let key=d.val(0)?;
  let name=match key{
   ScVal::Vec(mut v) if !v.is_empty()=>match v.remove(0){
    ScVal::Symbol(name)=>name,
    _=>return Err(())
   },
   _=>return Err(()),
  };
  let value=d.val(0)?;
  if fields.iter().any(|(k,_)|k==&name){return Err(());}
  fields.push((name,value));
 }
 if d.pos!=raw.len(){return Err(());}
 Ok(fields)
}
fn value<'a>(fields:&'a [(String,ScVal)],key:&str)->Option<&'a ScVal>{
 fields.iter().find(|(k,_)|k==key).map(|(_,v)|v)
}
/// Requires reviewed executable hashes as a prerequisite, so upgrade drift
/// never acquires a false claim about authorization semantics.
pub fn assess(reply:&Value,network_ledger:u64)->Result<Value,AdminObservationUnavailable>{
 let code=governance_code::assess(reply,network_ledger).map_err(|_|())?;
 if code["all_executable_hashes_match_release"]!=true{return Err(().into());}
 let entries=reply["entries"].as_array().ok_or(())?;
 let keys=governance_code::ledger_keys();
 let mut records:Vec<Value>=Vec::with_capacity(3);
 let mut same_admin=true;
 let mut unchanged=true;
 for (i,(name,id)) in CID.iter().enumerate(){
  let key=keys[i];
  let entry=entries.iter().find(|v|v["key"]==key).ok_or(())?;
  let data=parse_instance(entry["xdr"].as_str().ok_or(())?,key)?;
  let current=public_account(value(&data,"Admin").ok_or(())?)?;
  let pending=value(&data,"PendingAdmin").map(public_account).transpose()?;
  let paused=if i==2{
   let corridor=public_contract(value(&data,"CorridorRegistry").ok_or(())?)?;
   let policy=public_contract(value(&data,"PolicyRegistry").ok_or(())?)?;
   if corridor!=CID[0].1||policy!=CID[1].1{return Err(().into());}
   if value(&data,"Paused").is_some(){return Err(().into());}
   None
  }else{
   match value(&data,"Paused"){Some(ScVal::Bool(v))=>Some(*v),_=>return Err(().into())}
  };
  if i==2&&pending.is_some(){return Err(().into());}
  unchanged&=current==ADMIN_RELEASE;
  if i!=0{same_admin&=current==records[0]["current_administrator"];}
  records.push(json!({
    "name":name,"contract_id":id,"current_administrator":current,
    "pending_administrator":pending,"paused":paused,
    "matches_deployment_administrator":current==ADMIN_RELEASE
  }));
 }
 Ok(json!({
  "schema_version":1,"network":"testnet",
  "source":"stellar-rpc/getLedgerEntries/contract-instance-storage",
  "observed_ledger_sequence":code["observed_ledger_sequence"],
  "reviewed_release_executable_hashes_confirmed":true,
  "administrator_entries_read_from_current_storage":true,
  "same_administrator_for_all_contracts":same_admin,
  "all_administrators_match_deployment":unchanged,
  "release_administrator":ADMIN_RELEASE,
  "contracts":records,
  "signer_possession_verified":false,
  "fee_collection_enabled":false,"payment_execution_enabled":false,"privacy_verified":false
 }))
}
#[cfg(test)]
mod tests{
 use super::*;
 const H:[&str;3]=[
 "588d17f99850272f2f18e6ee407d94329b4f8ae415c2f6b71993cf59f4139099",
 "856186ba3dca1feff010c670bd1ae9818bf69e284304273f943745603b9a7912",
 "66b40fe5ee4f704a91acf39922ed130cc1eb4fc0cdc3c5ee5a30614921f4aa81"
 ];
 fn u(out:&mut Vec<u8>,n:u32){out.extend_from_slice(&n.to_be_bytes());}
 fn symbol(out:&mut Vec<u8>,s:&str){
  u(out,15);u(out,s.len() as u32);out.extend_from_slice(s.as_bytes());
  out.extend(vec![0; (4-s.len()%4)%4]);
 }
 fn account(out:&mut Vec<u8>,addr:&str){
  u(out,18);u(out,0);u(out,0);
  out.extend_from_slice(&crate::wallet::decode_account_address(addr).unwrap());
 }
 fn contract(out:&mut Vec<u8>,contract_id:&str){
  // StrKey C address has CRC16 XModem. Check local fixture roundtrip.
  let key=crate::governance_code::decode_base64(
   if contract_id==CID[0].1{governance_code::ledger_keys()[0]}
   else{governance_code::ledger_keys()[1]}).unwrap();
  u(out,18);u(out,1);out.extend_from_slice(&key[8..40]);
 }
 fn encode64(data:&[u8])->String{
  const ABC:&[u8]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let mut out=String::new();
  for b in data.chunks(3){
   let a=b[0];let c=*b.get(1).unwrap_or(&0);let d=*b.get(2).unwrap_or(&0);
   out.push(ABC[(a>>2)as usize] as char);
   out.push(ABC[(((a&3)<<4)|(c>>4))as usize] as char);
   out.push(if b.len()>1{ABC[(((c&15)<<2)|(d>>6))as usize] as char}else{'='});
   out.push(if b.len()>2{ABC[(d&63)as usize] as char}else{'='});
  }
  out
 }
 fn fixture_entry(i:usize,admin_addr:&str,pending:Option<&str>)->String{
  let k=governance_code::decode_base64(governance_code::ledger_keys()[i]).unwrap();
  let mut b=vec![];u(&mut b,6);u(&mut b,1);b.extend_from_slice(&k[8..40]);
  for tag in [20,1,19,0]{u(&mut b,tag);}
  for h in (0..64).step_by(2){b.push(u8::from_str_radix(&H[i][h..h+2],16).unwrap());}
  u(&mut b,1);u(&mut b,if i==2{3}else{2+u32::from(pending.is_some())});
  let mut entry=|name:&str,write:&dyn Fn(&mut Vec<u8>)|{
   u(&mut b,16);u(&mut b,1);u(&mut b,1);symbol(&mut b,name);write(&mut b);
  };
  entry("Admin",&|v|account(v,admin_addr));
  if i==2{
   entry("CorridorRegistry",&|v|contract(v,CID[0].1));
   entry("PolicyRegistry",&|v|contract(v,CID[1].1));
  }else{
   if let Some(next)=pending{entry("PendingAdmin",&|v|account(v,next));}
   entry("Paused",&|v|{u(v,0);u(v,0);});
  }
  encode64(&b)
 }
 fn reply(admins:[&str;3],pending:Option<&str>)->Value{
  json!({"latestLedger":5244400,"entries":(0..3).map(|i|json!({
   "key":governance_code::ledger_keys()[i],
   "xdr":fixture_entry(i,admins[i],if i==0{pending}else{None}),
   "lastModifiedLedgerSeq":5244300,"liveUntilLedgerSeq":5249000
  })).collect::<Vec<_>>()})
 }
 #[test]fn real_strkey_roundtrips_from_admin_public_key(){
  let key=crate::wallet::decode_account_address(ADMIN_RELEASE).unwrap();
  assert_eq!(strkey(6<<3,key),ADMIN_RELEASE);
 }
 #[test]fn current_admin_matches_original_for_all_three_instances(){
  let v=reply([ADMIN_RELEASE;3],None);
  let out=assess(&v,5244398).unwrap();
  assert_eq!(out["all_administrators_match_deployment"],true);
  assert_eq!(out["same_administrator_for_all_contracts"],true);
  assert_eq!(out["signer_possession_verified"],false);
  assert_eq!(out["fee_collection_enabled"],false);
 }
 #[test]fn legitimate_two_step_recovery_is_visible_without_signing(){
  let replacement="GBBCOFZZ3RDQHTC662EVM3UO5SAXQEZB6DL64HLEJYEYJ4KBVL3CDLTE";
  let staged=assess(&reply([ADMIN_RELEASE;3],Some(replacement)),5244400).unwrap();
  assert_eq!(staged["contracts"][0]["pending_administrator"],replacement);
  let migrated=assess(&reply([replacement,ADMIN_RELEASE,ADMIN_RELEASE],None),5244400).unwrap();
  assert_eq!(migrated["all_administrators_match_deployment"],false);
  assert_eq!(migrated["same_administrator_for_all_contracts"],false);
  assert_eq!(migrated["contracts"][0]["current_administrator"],replacement);
 }
 #[test]fn code_drift_invalidate_authority_semantics(){
  let mut r=reply([ADMIN_RELEASE;3],None);
  let v=r["entries"][1]["xdr"].as_str().unwrap().to_string();
  let mut x=governance_code::decode_base64(&v).unwrap();
  x[56]=0xf0;
  r["entries"][1]["xdr"]=json!(encode64(&x));
  assert!(assess(&r,5244400).is_err());
 }
 #[test]fn malformed_instance_storage_is_not_false_administrator_proof(){
  let base=reply([ADMIN_RELEASE;3],None);
  for (field,value) in [
   ("key",json!("wrong")),("liveUntilLedgerSeq",json!(1))
  ]{
   let mut x=base.clone();
   x["entries"][0][field]=value;
   assert!(assess(&x,5244400).is_err());
  }
  let original=base["entries"][0]["xdr"].as_str().unwrap();
  let bytes=governance_code::decode_base64(original).unwrap();
  for broken in [
   &bytes[..bytes.len()-1],&bytes[..96],&bytes[..92]
  ]{
   let mut x=base.clone();
   x["entries"][0]["xdr"]=json!(encode64(broken));
   assert!(assess(&x,5244400).is_err());
  }
 }
}
