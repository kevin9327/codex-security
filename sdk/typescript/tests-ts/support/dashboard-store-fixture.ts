import { readFileSync } from "node:fs";
import { SqliteFindingsStore } from "../../src/server/sqlite-store.js";
import type { DashboardQuery } from "../../src/server/dashboard-types.js";

async function main() {
  const query = JSON.parse(readFileSync(0, "utf8")) as DashboardQuery;
  const store = new SqliteFindingsStore(process.env);
  await store.initialize();
  const result = await store.dashboard(query);
  let retainedError: string | undefined;
  try {
    await store.list({ limit: 1, offset: 0 });
  } catch (error) {
    retainedError = (error as Error).message;
  }
  process.stdout.write(JSON.stringify({ result, retainedError }));
}
void main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
