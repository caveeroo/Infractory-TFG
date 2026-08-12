import { CamelCasePlugin, Kysely, Migrator, PostgresDialect, type MigrationProvider } from "kysely";
import pg from "pg";
import { migrations } from "./migrations.js";

export type Database = Record<string, never>;

export function createDatabase(connectionString: string): Kysely<Database> {
  return new Kysely<Database>({
    dialect: new PostgresDialect({ pool: new pg.Pool({ connectionString, max: 12, idleTimeoutMillis: 30_000 }) }),
    plugins: [new CamelCasePlugin()]
  });
}

export async function migrateDatabase(db: Kysely<Database>): Promise<void> {
  const provider: MigrationProvider = { async getMigrations() { return migrations; } };
  const result = await new Migrator({ db, provider, allowUnorderedMigrations: false }).migrateToLatest();
  for (const item of result.results ?? []) if (item.status === "Error") throw new Error(`Migration ${item.migrationName} failed`);
}
