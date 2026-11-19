import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const StellarSdk = require("/home/laughter/Projects/stealthbridge-main/stealthbridge-contracts/tools/smart-account-preflight/node_modules/@stellar/stellar-sdk");

const { Keypair, TransactionBuilder, Networks, Operation, BASE_FEE, rpc } = StellarSdk;

async function main() {
  const kp = Keypair.random();
  const friendbot = await fetch(`https://friendbot.stellar.org/?addr=${kp.publicKey()}`);
  if (!friendbot.ok) {
    throw new Error(`Friendbot failed: ${friendbot.status}`);
  }
  const server = new rpc.Server("https://soroban-testnet.stellar.org");
  const account = await server.getAccount(kp.publicKey());
  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(
      Operation.manageData({
        name: "sb_m5_intent",
        value: Buffer.from("milestone5-disposable-e2e"),
      }),
    )
    .setTimeout(60)
    .build();
  tx.sign(kp);
  const sendRes = await server.sendTransaction(tx);
  if (sendRes.status === "ERROR") {
    throw new Error(`sendTransaction rejected: ${JSON.stringify(sendRes)}`);
  }
  let txRes;
  for (let i = 0; i < 20; i++) {
    txRes = await server.getTransaction(sendRes.hash);
    if (txRes.status !== "NOT_FOUND") break;
    await new Promise((r) => setTimeout(r, 1500));
  }
  if (!txRes || txRes.status !== "SUCCESS") {
    throw new Error(`Transaction did not finalize cleanly: ${JSON.stringify(txRes)}`);
  }
  console.log(
    JSON.stringify({
      disposable_account: kp.publicKey(),
      tx_hash: sendRes.hash,
      status: txRes.status,
      ledger: txRes.ledger,
    }),
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
