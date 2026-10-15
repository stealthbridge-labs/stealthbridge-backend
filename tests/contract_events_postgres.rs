//! PostgreSQL integration: durable source-only public-event idempotence.
//! Synthetic event IDs and tx hashes; no private event values are persisted.
use serde_json::json;
use sqlx::PgPool;
use stealthbridge_backend::ledger_events::{
 load_progress,parse_events,record_event_page,JournalError,Progress,EXAMPLE_CONTRACT,
};
#[tokio::test]
async fn event_journal_recovers_after_restarts_without_duplicate_or_conflicting_rows(){
 let url=std::env::var("DATABASE_URL").expect("CI PostgreSQL required");
 let pool=PgPool::connect(&url).await.expect("connect");
 sqlx::migrate!("./migrations").run(&pool).await.expect("migrate");
 let contract=EXAMPLE_CONTRACT;
 sqlx::query("DELETE FROM stellar_contract_event_journal WHERE contract_id=$1")
  .bind(contract).execute(&pool).await.unwrap();
 sqlx::query("DELETE FROM stellar_contract_event_cursors WHERE contract_id=$1")
  .bind(contract).execute(&pool).await.unwrap();
 let before=load_progress(&pool,contract,100).await.unwrap();
 assert_eq!(before,Progress{start_ledger:100,cursor:None});
 let id="0000000000000000100-0000000001";
 let ev=|hash:&str|json!({"id":id,"type":"contract","contractId":contract,
  "txHash":hash,"ledger":100,
  "topic":["IN_MEMORY_ONLY_PRIVATE_PROOF_SHOULD_NEVER_BE_STORED"],
  "value":"IN_MEMORY_ONLY_CONFIDENTIAL_EVENT_VALUE"});
 let rpc=json!({"latestLedger":101,"oldestLedger":90,"cursor":id,
  "events":[ev(&"a".repeat(64))]});
 let page=parse_events(&rpc,contract,&before).unwrap();
 let after=record_event_page(&pool,contract,&before,&page).await.unwrap();
 assert_eq!(after.cursor.as_deref(),Some(id));
 assert_eq!(load_progress(&pool,contract,1).await.unwrap(),after);
 let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM stellar_contract_event_journal \
   WHERE network='testnet' AND contract_id=$1").bind(contract).fetch_one(&pool).await.unwrap();
 assert_eq!(count,1);
 let activity_page=stealthbridge_backend::ledger_events::read_activity(
    &pool,&stealthbridge_backend::ledger_events::ActivityOptions{
       limit:Some(1),contract_id:Some(contract.to_owned()),before:None,
    }).await.expect("journal activity read");
 assert_eq!(activity_page.network,"testnet");
 assert_eq!(activity_page.source,"stored-public-testnet-metadata");
 assert_eq!(activity_page.observation_status,"checkpoint-present");
 assert!(!activity_page.payment_execution_enabled);
 assert_eq!(activity_page.items.len(),1);
 assert_eq!(activity_page.items[0].id,id);
 assert_eq!(activity_page.items[0].contract_id,contract);
 assert_eq!(activity_page.items[0].tx_hash,"a".repeat(64));
 assert!(activity_page.contracts.iter().any(|c|c.contract_id==contract));
 assert!(activity_page.next_cursor.is_none());
 let serialized=serde_json::to_string(&activity_page).unwrap();
 assert!(!serialized.contains("IN_MEMORY_ONLY_PRIVATE_PROOF_SHOULD_NEVER_BE_STORED"));
 assert!(!serialized.contains("IN_MEMORY_ONLY_CONFIDENTIAL_EVENT_VALUE"));
 let snapshot=stealthbridge_backend::ledger_events::diagnostics(&pool).await.unwrap();
 assert!(snapshot.tracked_contracts>=1);
 assert!(snapshot.public_event_rows>=1);
 assert!(snapshot.oldest_cursor_age_seconds.is_some());
 assert!(snapshot.earliest_resume_ledger.is_some());
 let persisted:String=sqlx::query_scalar("SELECT transaction_hash FROM stellar_contract_event_journal \
   WHERE network='testnet' AND contract_id=$1").bind(contract).fetch_one(&pool).await.unwrap();
 assert_eq!(persisted,"a".repeat(64));
 // Malicious/duplicate events cannot be applied again as a second journal row.
 assert!(matches!(
  record_event_page(&pool,contract,&before,&page).await,
  Err(JournalError::StaleCheckpoint)));
 let replay=json!({"latestLedger":101,"oldestLedger":90,
  "cursor":"0000000000000000100-0000000002",
  "events":[ev(&"a".repeat(64))]});
 let replay_page=parse_events(&replay,contract,&after).unwrap();
 let replayed=record_event_page(&pool,contract,&after,&replay_page).await.unwrap();
 let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM stellar_contract_event_journal \
   WHERE network='testnet' AND contract_id=$1").bind(contract).fetch_one(&pool).await.unwrap();
 assert_eq!(count,1);
 // Same event ID with inconsistent transaction hash is never silently merged.
 let malicious=json!({"latestLedger":102,"oldestLedger":90,
  "cursor":"0000000000000000100-0000000003",
  "events":[ev(&"b".repeat(64))]});
 let broken=parse_events(&malicious,contract,&replayed).unwrap();
 assert!(matches!(
  record_event_page(&pool,contract,&replayed,&broken).await,
  Err(JournalError::ConflictingEvent)));
 assert_eq!(load_progress(&pool,contract,1).await.unwrap(),replayed);
 let empty=json!({"latestLedger":103,"oldestLedger":90,"events":[]});
 let done=parse_events(&empty,contract,&replayed).unwrap();
 let completed=record_event_page(&pool,contract,&replayed,&done).await.unwrap();
 assert_eq!(completed.start_ledger,104);
 assert!(completed.cursor.is_none());
 assert_eq!(load_progress(&pool,contract,1).await.unwrap(),completed);
 // A deterministic second PUBLIC metadata fixture exercises stable descending
 // keyset pagination. It is never presented as a real Testnet transaction.
 let second_id="0000000000000000101-0000000001";
 sqlx::query("INSERT INTO stellar_contract_event_journal \
   (network,contract_id,event_id,transaction_hash,ledger_sequence) \
   VALUES ('testnet',$1,$2,$3,101)")
    .bind(contract).bind(second_id).bind("b".repeat(64))
    .execute(&pool).await.unwrap();
 let first_page=stealthbridge_backend::ledger_events::read_activity(
   &pool,&stealthbridge_backend::ledger_events::ActivityOptions{
      limit:Some(1),contract_id:Some(contract.to_owned()),before:None,
   }).await.unwrap();
 assert_eq!(first_page.items.len(),1);
 assert_eq!(first_page.items[0].id,second_id);
 let after=first_page.next_cursor.expect("second page exists");
 assert_eq!(after,format!("{second_id}.{contract}"));
 let older=stealthbridge_backend::ledger_events::read_activity(
   &pool,&stealthbridge_backend::ledger_events::ActivityOptions{
      limit:Some(1),contract_id:Some(contract.to_owned()),before:Some(after),
   }).await.unwrap();
 assert_eq!(older.items.len(),1);
 assert_eq!(older.items[0].id,id);
 assert!(older.next_cursor.is_none());
 // Never store raw RPC topics, values, ciphertext or amount witnesses.
 let columns:Vec<String>=sqlx::query_scalar(
  "SELECT column_name FROM information_schema.columns WHERE table_name='stellar_contract_event_journal'")
  .fetch_all(&pool).await.unwrap();
 for private in ["value","topic","amount","proof","witness","ciphertext","recipient"]{
  assert!(!columns.iter().any(|name|name==private));
 }
 sqlx::query("DELETE FROM stellar_contract_event_journal WHERE contract_id=$1")
  .bind(contract).execute(&pool).await.unwrap();
 sqlx::query("DELETE FROM stellar_contract_event_cursors WHERE contract_id=$1")
  .bind(contract).execute(&pool).await.unwrap();
}
