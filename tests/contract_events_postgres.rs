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
