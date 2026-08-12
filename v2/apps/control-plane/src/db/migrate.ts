import { loadConfig } from "../config.js";
import { createDatabase, migrateDatabase } from "./database.js";
import { makeWorkerUtils } from "graphile-worker";

const config = loadConfig();
if (!config.databaseUrl) throw new Error("DATABASE_URL is required to migrate");
const db = createDatabase(config.databaseUrl);
try {
  await migrateDatabase(db);
  const workerUtils = await makeWorkerUtils({ connectionString: config.databaseUrl });
  try { await workerUtils.migrate(); } finally { await workerUtils.release(); }
} finally {
  await db.destroy();
}
