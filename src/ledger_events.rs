//! Bounded, opt-in public Stellar Testnet contract event journaling.
//! NEVER store topics, values, proofs, private amounts or wallet data.
//! getEvents event IDs are observer identifiers, NOT payment confirmations.
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use sqlx::{PgPool,Row};

pub const PAGE_LIMIT:usize=25;
const MAX_CONTRACTS:usize=5;
const MAX_CURSOR_BYTES:usize=256;
pub const EXAMPLE_CONTRACT:&str="CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

#[derive(Debug)]
pub enum JournalError{
 InvalidContract,InvalidPage,PrunedHistory,ConflictingEvent,StaleCheckpoint,
 Database(sqlx::Error),
}
impl From<sqlx::Error> for JournalError{
 fn from(e:sqlx::Error)->Self{Self::Database(e)}
}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Progress{
 pub start_ledger:u64,
 pub cursor:Option<String>,
}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct PublicEvent{
 pub id:String,
 pub contract_id:String,
 pub tx_hash:String,
 pub ledger:u64,
}
#[derive(Debug)]
pub struct EventPage{
 pub latest_ledger:u64,
 pub oldest_ledger:u64,
 pub cursor:Option<String>,
 pub events:Vec<PublicEvent>,
}
fn crc_xmodem(data:&[u8])->u16{
 let mut crc=0_u16;
 for value in data{
  crc^=u16::from(*value)<<8;
  for _ in 0..8{
   crc=if crc&0x8000!=0{(crc<<1)^0x1021}else{crc<<1};
  }
 }
 crc
}
/// Read-only StrKey C-address checksum verification; never authenticates an
/// operator or proves a contract exists in a Stellar ledger.
pub fn valid_contract_id(address:&str)->bool{
 if address.len()!=56||!address.starts_with('C'){return false;}
 let mut out=[0_u8;35];
 let(mut acc,mut bits,mut pos)=(0_u32,0_u32,0_usize);
 for byte in address.bytes(){
  let v=match byte{b'A'..=b'Z'=>u32::from(byte-b'A'),
    b'2'..=b'7'=>u32::from(byte-b'2'+26),_=>return false};
  acc=(acc<<5)|v;
  bits+=5;
  if bits>=8{
   bits-=8;
   if pos>=out.len(){return false;}
   out[pos]=((acc>>bits)&255) as u8;
   pos+=1;
   acc&=(1<<bits)-1;
  }
 }
 pos==out.len()&&bits==0&&out[0]==2<<3&&
   crc_xmodem(&out[..33])==u16::from_le_bytes([out[33],out[34]])
}
fn valid_cursor(v:&str)->bool{
 !v.is_empty()&&v.len()<=MAX_CURSOR_BYTES&&v.is_ascii()&&
  !v.bytes().any(|x|x.is_ascii_control())
}
fn valid_event_id(value:&str)->bool{
 value.len()==30&&value.as_bytes()[19]==b'-'&&
 value.bytes().enumerate().all(|(i,b)|i==19||b.is_ascii_digit())
}
fn valid_hash(value:&str)->bool{
 value.len()==64&&value.bytes().all(|x|x.is_ascii_hexdigit())
}
pub fn configured_contracts(raw:&str)->Result<Vec<String>,JournalError>{
 if raw.is_empty(){return Ok(vec![]);}
 let values:Vec<String>=raw.split(',').map(str::trim).map(str::to_owned).collect();
 if values.is_empty()||values.len()>MAX_CONTRACTS||
    values.iter().any(|x|!valid_contract_id(x))||
    values.iter().enumerate().any(|(i,x)|values[..i].contains(x)){
    return Err(JournalError::InvalidContract);
 }
 Ok(values)
}
pub fn rpc_params(contract_id:&str,progress:&Progress)->Result<Value,JournalError>{
 if !valid_contract_id(contract_id)||progress.start_ledger==0||
    progress.start_ledger>i64::MAX as u64{return Err(JournalError::InvalidContract);}
 let mut params=json!({
  "filters":[{"type":"contract","contractIds":[contract_id]}],
  "pagination":{"limit":PAGE_LIMIT},
  "xdrFormat":"base64"
 });
 if let Some(cursor)=&progress.cursor{
  if !valid_cursor(cursor){return Err(JournalError::InvalidPage);}
  params["pagination"]["cursor"]=json!(cursor);
 }else{
  params["startLedger"]=json!(progress.start_ledger);
 }
 Ok(params)
}
pub fn parse_events(
 result:&Value,contract_id:&str,progress:&Progress,
)->Result<EventPage,JournalError>{
 if !valid_contract_id(contract_id){return Err(JournalError::InvalidContract);}
 let latest=result.get("latestLedger").and_then(Value::as_u64).ok_or(JournalError::InvalidPage)?;
 let oldest=result.get("oldestLedger").and_then(Value::as_u64).ok_or(JournalError::InvalidPage)?;
 if oldest==0||oldest>latest||latest>i64::MAX as u64||progress.start_ledger>latest {
  return Err(JournalError::InvalidPage);
 }
 if progress.start_ledger<oldest{
  // RPC retains a finite window. Do not skip history without operator signoff.
  return Err(JournalError::PrunedHistory);
 }
 let values=result.get("events").and_then(Value::as_array).ok_or(JournalError::InvalidPage)?;
 if values.len()>PAGE_LIMIT{return Err(JournalError::InvalidPage);}
 let cursor=result.get("cursor").and_then(Value::as_str);
 if let Some(c)=cursor{
  if !valid_cursor(c)||progress.cursor.as_deref()==Some(c){
    return Err(JournalError::InvalidPage);
  }
 }
 if !values.is_empty()&&cursor.is_none(){return Err(JournalError::InvalidPage);}
 let mut events=Vec::with_capacity(values.len());
 let mut previous:Option<String>=None;
 for item in values{
  if item.get("type").and_then(Value::as_str)!=Some("contract")||
     item.get("contractId").and_then(Value::as_str)!=Some(contract_id){
      return Err(JournalError::InvalidPage);
  }
  let id=item.get("id").and_then(Value::as_str).ok_or(JournalError::InvalidPage)?;
  let hash=item.get("txHash").and_then(Value::as_str).ok_or(JournalError::InvalidPage)?;
  let ledger=item.get("ledger").and_then(Value::as_u64).ok_or(JournalError::InvalidPage)?;
  if !valid_event_id(id)||!valid_hash(hash)||ledger<oldest||ledger>latest||
     ledger<progress.start_ledger||
     previous.as_deref().is_some_and(|last|id<=last){
      return Err(JournalError::InvalidPage);
  }
  previous=Some(id.to_owned());
  events.push(PublicEvent{
   id:id.to_owned(),contract_id:contract_id.to_owned(),
   tx_hash:hash.to_ascii_lowercase(),ledger,
  });
 }
 Ok(EventPage{
  latest_ledger:latest,oldest_ledger:oldest,
  cursor:cursor.map(str::to_owned),events,
 })
}
pub fn next_progress(before:&Progress,page:&EventPage)->Result<Progress,JournalError>{
 let(start_ledger,cursor)=if page.events.is_empty(){
  (page.latest_ledger.checked_add(1).ok_or(JournalError::InvalidPage)?,None)
 }else{
  // A cursor is opaque to the client, but the most recently observed ledger
  // is verified public event metadata. Persist its sequence as our retention
  // floor. Keeping the *initial* bootstrap ledger here causes a healthy
  // long-lived cursor (or a resumed worker) to be falsely classified as
  // pruned as soon as RPC's rolling oldestLedger moves past the bootstrap.
  // The cursor still takes precedence: rpc_params omits startLedger whenever
  // cursor is present, per the Stellar getEvents pagination contract.
  let last=page.events.last().ok_or(JournalError::InvalidPage)?.ledger;
  if last<before.start_ledger||last>page.latest_ledger||page.cursor.is_none(){
   return Err(JournalError::InvalidPage);
  }
  (last,page.cursor.clone())
 };
 Ok(Progress{start_ledger,cursor})
}
pub async fn load_progress(
 pool:&PgPool,contract_id:&str,bootstrap_start:u64,
)->Result<Progress,JournalError>{
 if !valid_contract_id(contract_id)||bootstrap_start==0||
  bootstrap_start>i64::MAX as u64{return Err(JournalError::InvalidContract);}
 let row=sqlx::query("SELECT next_start_ledger,pagination_cursor \
   FROM stellar_contract_event_cursors WHERE network='testnet' AND contract_id=$1")
  .bind(contract_id).fetch_optional(pool).await?;
 match row{
  Some(row)=>{
   let value:i64=row.try_get("next_start_ledger")?;
   let cursor:Option<String>=row.try_get("pagination_cursor")?;
   if value<=0||cursor.as_deref().is_some_and(|x|!valid_cursor(x)){
    return Err(JournalError::InvalidPage);
   }
   Ok(Progress{start_ledger:value as u64,cursor})
  }
  None=>Ok(Progress{start_ledger:bootstrap_start,cursor:None}),
 }
}
/// The entire page (idempotent event receipts + resume cursor) commits in
/// one transaction. A malformed/pruned/out-of-order response never advances.
pub async fn record_event_page(
 pool:&PgPool,contract_id:&str,before:&Progress,page:&EventPage,
)->Result<Progress,JournalError>{
 if !valid_contract_id(contract_id)||before.start_ledger==0||
  before.start_ledger>i64::MAX as u64||
  before.cursor.as_deref().is_some_and(|s|!valid_cursor(s))||
  page.events.len()>PAGE_LIMIT||page.oldest_ledger>before.start_ledger||
  page.latest_ledger<before.start_ledger||
  page.events.iter().any(|e|e.contract_id!=contract_id||!valid_event_id(&e.id)||
   !valid_hash(&e.tx_hash)||e.ledger<before.start_ledger||e.ledger>page.latest_ledger){
    return Err(JournalError::InvalidPage);
 }
 let after=next_progress(before,page)?;
 if after.start_ledger>i64::MAX as u64{return Err(JournalError::InvalidPage);}
 let mut tx=pool.begin().await?;
 sqlx::query("INSERT INTO stellar_contract_event_cursors \
  (network,contract_id,next_start_ledger,pagination_cursor) VALUES ('testnet',$1,$2,$3) \
  ON CONFLICT(network,contract_id) DO NOTHING")
  .bind(contract_id).bind(before.start_ledger as i64).bind(&before.cursor)
  .execute(&mut *tx).await?;
 let row=sqlx::query("SELECT next_start_ledger,pagination_cursor FROM stellar_contract_event_cursors \
  WHERE network='testnet' AND contract_id=$1 FOR UPDATE")
  .bind(contract_id).fetch_one(&mut *tx).await?;
 let saved:i64=row.try_get("next_start_ledger")?;
 let stored:Option<String>=row.try_get("pagination_cursor")?;
 if saved!=before.start_ledger as i64||stored!=before.cursor{
  return Err(JournalError::StaleCheckpoint);
 }
 for event in &page.events{
  let created=sqlx::query("INSERT INTO stellar_contract_event_journal \
    (network,contract_id,event_id,transaction_hash,ledger_sequence) \
    VALUES('testnet',$1,$2,$3,$4) \
    ON CONFLICT(network,contract_id,event_id) DO NOTHING RETURNING event_id")
   .bind(contract_id).bind(&event.id).bind(&event.tx_hash)
   .bind(event.ledger as i64).fetch_optional(&mut *tx).await?;
  if created.is_none(){
    let prior=sqlx::query("SELECT transaction_hash,ledger_sequence \
      FROM stellar_contract_event_journal WHERE network='testnet' \
      AND contract_id=$1 AND event_id=$2 FOR UPDATE")
     .bind(contract_id).bind(&event.id).fetch_one(&mut *tx).await?;
    let prior_hash:String=prior.try_get("transaction_hash")?;
    let prior_ledger:i64=prior.try_get("ledger_sequence")?;
    if prior_hash!=event.tx_hash||prior_ledger!=event.ledger as i64{
      return Err(JournalError::ConflictingEvent);
    }
  }
 }
 sqlx::query("UPDATE stellar_contract_event_cursors SET \
    next_start_ledger=$1,pagination_cursor=$2,observed_at=now() \
    WHERE network='testnet' AND contract_id=$3")
  .bind(after.start_ledger as i64).bind(&after.cursor).bind(contract_id)
  .execute(&mut *tx).await?;
 tx.commit().await?;
 Ok(after)
}

/// Safe aggregate state only. Never include contract IDs, event IDs, hashes,
/// topics, private values, principals, wallet identities or RPC payloads in
/// public or operator metrics.
#[derive(Debug)]
pub struct JournalDiagnostics{
 pub tracked_contracts:i64,
 pub public_event_rows:i64,
 pub oldest_cursor_age_seconds:Option<i64>,
 pub earliest_resume_ledger:Option<i64>,
}
pub async fn diagnostics(pool:&PgPool)->Result<JournalDiagnostics,sqlx::Error>{
 let row=sqlx::query("SELECT     (SELECT COUNT(*) FROM stellar_contract_event_cursors WHERE network='testnet') AS tracked_contracts,     (SELECT COUNT(*) FROM stellar_contract_event_journal WHERE network='testnet') AS public_event_rows,     (SELECT CASE WHEN COUNT(*)=0 THEN NULL ELSE GREATEST(0,EXTRACT(EPOCH FROM (now()-MIN(observed_at)))::bigint) END FROM stellar_contract_event_cursors WHERE network='testnet') AS cursor_age_seconds,     (SELECT MIN(next_start_ledger) FROM stellar_contract_event_cursors        WHERE network='testnet') AS earliest_resume_ledger")
  .fetch_one(pool).await?;
 Ok(JournalDiagnostics{
  tracked_contracts:row.try_get("tracked_contracts")?,
  public_event_rows:row.try_get("public_event_rows")?,
  oldest_cursor_age_seconds:row.try_get("cursor_age_seconds")?,
  earliest_resume_ledger:row.try_get("earliest_resume_ledger")?,
 })
}

/// Historical *public* Testnet journal metadata only. These values are not
/// on-chain execution receipts, verified private transfers or bank payouts.
#[derive(Debug, Serialize)]
pub struct ActivityContract {
 pub contract_id:String,
 pub next_start_ledger:i64,
 pub observed_at_unix:String,
}
#[derive(Debug, Serialize)]
pub struct ActivityEvent {
 pub id:String,
 pub contract_id:String,
 pub tx_hash:String,
 pub ledger_sequence:i64,
 pub observed_at_unix:String,
}
#[derive(Debug, Serialize)]
pub struct ActivityPage {
 pub network:&'static str,
 pub source:&'static str,
 pub observation_status:&'static str,
 pub payment_execution_enabled:bool,
 pub contracts:Vec<ActivityContract>,
 pub items:Vec<ActivityEvent>,
 pub next_cursor:Option<String>,
}
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityOptions {
 pub limit:Option<u32>,
 pub contract_id:Option<String>,
 pub before:Option<String>,
}
fn parse_public_cursor(cursor:&str)->Result<(&str,&str),JournalError>{
 let (id,contract)=cursor.split_once('.').ok_or(JournalError::InvalidPage)?;
 if !valid_event_id(id)||!valid_contract_id(contract)||
    cursor.len()!=id.len()+1+contract.len() {
     return Err(JournalError::InvalidPage);
 }
 Ok((id,contract))
}
pub fn valid_activity_options(options:&ActivityOptions)->Result<u32,JournalError>{
 let limit=options.limit.unwrap_or(15);
 if !(1..=PAGE_LIMIT as u32).contains(&limit)||
  options.contract_id.as_ref().is_some_and(|x|!valid_contract_id(x)){
   return Err(JournalError::InvalidPage);
 }
 if let Some(before)=options.before.as_deref(){
   let (_,cursor_contract)=parse_public_cursor(before)?;
   if options.contract_id.as_deref().is_some_and(|c|c!=cursor_contract){
     return Err(JournalError::InvalidPage);
   }
 }
 Ok(limit)
}
/// One bounded page + at most five public cursor summaries. Use two prepared,
/// deterministic queries and never materialize private event XDR/payloads.
/// No RPC polling occurs in Vercel's request handling path.
pub async fn read_activity(
 pool:&PgPool,options:&ActivityOptions,
)->Result<ActivityPage,JournalError>{
 let limit=valid_activity_options(options)?;
 let cursors=sqlx::query(
  "SELECT contract_id,next_start_ledger,EXTRACT(EPOCH FROM observed_at)::bigint AS observed_unix \
   FROM stellar_contract_event_cursors WHERE network='testnet' ORDER BY contract_id LIMIT 6")
   .fetch_all(pool).await?;
 if cursors.len()>MAX_CONTRACTS{return Err(JournalError::InvalidPage);}
 let mut contracts=Vec::with_capacity(cursors.len());
 for row in cursors{
   let id:String=row.try_get("contract_id")?;
   let ledger:i64=row.try_get("next_start_ledger")?;
   let timestamp:i64=row.try_get("observed_unix")?;
   if !valid_contract_id(&id)||ledger<=0||timestamp<=0{
     return Err(JournalError::InvalidPage);
   }
   contracts.push(ActivityContract{
      contract_id:id,next_start_ledger:ledger,observed_at_unix:timestamp.to_string(),
   });
 }
 let before=options.before.as_deref().map(parse_public_cursor).transpose()?;
 let rows=sqlx::query(
  "SELECT contract_id,event_id,transaction_hash,ledger_sequence, \
   EXTRACT(EPOCH FROM observed_at)::bigint AS observed_unix \
   FROM stellar_contract_event_journal WHERE network='testnet' \
   AND ($1::varchar IS NULL OR contract_id=$1) \
   AND ($2::varchar IS NULL OR (event_id,contract_id)<($2::varchar,$3::varchar)) \
   ORDER BY event_id DESC,contract_id DESC LIMIT $4")
   .bind(options.contract_id.as_deref())
   .bind(before.map(|(id,_)|id))
   .bind(before.map(|(_,contract)|contract))
   .bind(i64::from(limit)+1)
   .fetch_all(pool).await?;
 let has_more=rows.len()>limit as usize;
 let mut items=Vec::with_capacity(limit as usize);
 for row in rows.into_iter().take(limit as usize){
  let id:String=row.try_get("event_id")?;
  let contract_id:String=row.try_get("contract_id")?;
  let tx_hash:String=row.try_get("transaction_hash")?;
  let ledger_sequence:i64=row.try_get("ledger_sequence")?;
  let observed:i64=row.try_get("observed_unix")?;
  if !valid_event_id(&id)||!valid_contract_id(&contract_id)||
     !valid_hash(&tx_hash)||ledger_sequence<=0||observed<=0||
     !contracts.iter().any(|c|c.contract_id==contract_id){
   return Err(JournalError::InvalidPage);
  }
  items.push(ActivityEvent{
    id,contract_id,tx_hash,ledger_sequence,observed_at_unix:observed.to_string(),
  });
 }
 let next_cursor=if has_more{
   items.last().map(|event|format!("{}.{}",event.id,event.contract_id))
 }else{None};
 Ok(ActivityPage{
  network:"testnet",source:"stored-public-testnet-metadata",
  observation_status:if contracts.is_empty(){"no-checkpoint"}else{"checkpoint-present"},
  payment_execution_enabled:false,contracts,items,next_cursor,
 })
}

#[cfg(test)]
mod tests{
 use super::*;
 fn progress()->Progress{Progress{start_ledger:100,cursor:None}}
 fn event(id:&str)->Value{
  json!({"id":id,"type":"contract","contractId":EXAMPLE_CONTRACT,
    "txHash":"a".repeat(64),"ledger":100,
    "topic":["AAAA"],"value":"NEVER_PERSIST_PRIVATE_EVENT_XDR"})
 }
 #[test]
 fn activity_filters_and_cursor_validation_are_bounded(){
  let contract=EXAMPLE_CONTRACT.to_owned();
  assert_eq!(valid_activity_options(&ActivityOptions::default()).unwrap(),15);
  let ok=ActivityOptions{
    limit:Some(25),contract_id:Some(contract.clone()),
    before:Some(format!("0000000000000000100-0000000001.{contract}")),
  };
  assert_eq!(valid_activity_options(&ok).unwrap(),25);
  for candidate in [
   ActivityOptions{limit:Some(0),..ActivityOptions::default()},
   ActivityOptions{limit:Some(26),..ActivityOptions::default()},
   ActivityOptions{contract_id:Some("C".repeat(56)),..ActivityOptions::default()},
   ActivityOptions{before:Some("0000000000000000100-0000000001".into()),..ActivityOptions::default()},
   ActivityOptions{before:Some(format!("0000000000000000100-0000000001.{contract}.evil")),..ActivityOptions::default()},
   ActivityOptions{contract_id:Some(contract.clone()),
     before:Some(format!("0000000000000000100-0000000001.{}", "C".repeat(56))),..ActivityOptions::default()},
  ]{
    assert!(valid_activity_options(&candidate).is_err());
  }
 }
 #[test]
 fn validates_strkey_and_hard_bounds(){
  assert!(valid_contract_id(EXAMPLE_CONTRACT));
  assert!(!valid_contract_id(&format!("{}A",&EXAMPLE_CONTRACT[..55])));
  assert!(!valid_contract_id("GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX"));
  assert_eq!(configured_contracts(EXAMPLE_CONTRACT).unwrap().len(),1);
  assert!(configured_contracts(&format!("{EXAMPLE_CONTRACT},{EXAMPLE_CONTRACT}")).is_err());
  assert!(configured_contracts(&[EXAMPLE_CONTRACT;6].join(",")).is_err());
  let a=rpc_params(EXAMPLE_CONTRACT,&progress()).unwrap();
  assert_eq!(a["startLedger"],json!(100));
  assert_eq!(a["pagination"]["limit"],json!(25));
  let cursor=Progress{start_ledger:100,cursor:Some("123-0".into())};
  let b=rpc_params(EXAMPLE_CONTRACT,&cursor).unwrap();
  assert!(b.get("startLedger").is_none());
  assert_eq!(b["pagination"]["cursor"],json!("123-0"));
 }
 #[test]
 fn parses_public_ids_without_capturing_confidential_xdr(){
  let id="0000000000000000100-0000000001";
  let payload=json!({"latestLedger":101,"oldestLedger":90,"cursor":id,"events":[event(id)]});
  let page=parse_events(&payload,EXAMPLE_CONTRACT,&progress()).unwrap();
  assert_eq!(page.events.len(),1);
  let serialized=serde_json::to_string(&json!({
    "id":page.events[0].id,"tx_hash":page.events[0].tx_hash
  })).unwrap();
  assert!(!serialized.contains("NEVER_PERSIST_PRIVATE_EVENT_XDR"));
  assert_eq!(next_progress(&progress(),&page).unwrap().cursor.as_deref(),Some(id));
  let clear=json!({"latestLedger":101,"oldestLedger":90,"events":[],"cursor":"final"});
  let next=parse_events(&clear,EXAMPLE_CONTRACT,&progress()).unwrap();
  assert_eq!(next_progress(&progress(),&next).unwrap().start_ledger,102);
 }
 #[test]
 fn event_cursor_retention_floor_advances_with_observed_ledger(){
  let progress=Progress{start_ledger:100,cursor:None};
  let event_id="0000000000000000101-0000000001";
  let payload=json!({"latestLedger":105,"oldestLedger":90,"cursor":event_id,
    "events":[{"id":event_id,"type":"contract","contractId":EXAMPLE_CONTRACT,
     "txHash":"a".repeat(64),"ledger":101}]});
  let page=parse_events(&payload,EXAMPLE_CONTRACT,&progress).unwrap();
  let resumed=next_progress(&progress,&page).unwrap();
  assert_eq!(resumed.start_ledger,101);
  assert_eq!(resumed.cursor.as_deref(),Some(event_id));
  let params=rpc_params(EXAMPLE_CONTRACT,&resumed).unwrap();
  assert!(params.get("startLedger").is_none());
  assert_eq!(params["pagination"]["cursor"],json!(event_id));
  // RPC retention can advance beyond the historical bootstrap ledger while
  // the still-live cursor remains safe to use. A genuine pruned cursor fails.
  let next=json!({"latestLedger":106,"oldestLedger":101,"cursor":"0000000000000000102-0000000001",
    "events":[{"id":"0000000000000000102-0000000001","type":"contract",
      "contractId":EXAMPLE_CONTRACT,"txHash":"b".repeat(64),"ledger":102}]});
  let second=parse_events(&next,EXAMPLE_CONTRACT,&resumed).unwrap();
  assert_eq!(next_progress(&resumed,&second).unwrap().start_ledger,102);
  let pruned=json!({"latestLedger":106,"oldestLedger":103,"cursor":"0000000000000000103-0000000001",
    "events":[]});
  assert!(matches!(parse_events(&pruned,EXAMPLE_CONTRACT,&resumed),
    Err(JournalError::PrunedHistory)));
 }
 #[test]
 fn rejects_pruning_malformed_events_and_out_of_order_pages(){
  let id="0000000000000000100-0000000001";
  let base=json!({"latestLedger":101,"oldestLedger":90,"cursor":id,"events":[event(id)]});
  assert!(matches!(parse_events(&base,EXAMPLE_CONTRACT,&Progress{
      start_ledger:89,cursor:None}),Err(JournalError::PrunedHistory)));
  let invalid=[
    json!({"latestLedger":101,"oldestLedger":90,"events":[event(id)]}),
    json!({"latestLedger":101,"oldestLedger":90,"cursor":id,"events":[event(id),event(id)]}),
    json!({"latestLedger":101,"oldestLedger":90,"cursor":id,"events":[{
      "id":id,"type":"contract","contractId":"wrong","txHash":"a".repeat(64),"ledger":100
    }]}),
    json!({"latestLedger":101,"oldestLedger":90,"cursor":id,"events":[{
      "id":id,"type":"contract","contractId":EXAMPLE_CONTRACT,
      "txHash":"a".repeat(64),"ledger":102
    }]}),
  ];
  for candidate in invalid{assert!(parse_events(&candidate,EXAMPLE_CONTRACT,&progress()).is_err());}
 }
}
