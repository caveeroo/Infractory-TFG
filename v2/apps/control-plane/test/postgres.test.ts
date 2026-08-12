import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { makeWorkerUtils } from "graphile-worker";
import { createDatabase, migrateDatabase, type Database } from "../src/db/database.js";
import { PostgresStore } from "../src/db/postgres-store.js";
import { EnvironmentService } from "../src/services/environment-service.js";
import type { Kysely } from "kysely";
import { sql } from "kysely";
import { CredentialService } from "../src/services/credential-service.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
describe.skipIf(!databaseUrl)("PostgreSQL persistence", () => {
  let db: Kysely<Database>; let store: PostgresStore; let schema = "";
  beforeAll(async () => {
    schema = `infractory_test_${randomUUID().replaceAll("-", "")}`;
    const admin = createDatabase(databaseUrl!); await admin.executeQuery({ sql: `create schema ${schema}`, parameters: [], query: {} as never }); await admin.destroy();
    const url = new URL(databaseUrl!); url.searchParams.set("options", `-c search_path=${schema},public`);
    db = createDatabase(url.toString()); await migrateDatabase(db);
    const worker = await makeWorkerUtils({ connectionString: databaseUrl! }); try { await worker.migrate(); } finally { await worker.release(); }
    store = new PostgresStore(db, true);
  });
  afterAll(async () => {
    if (store) await store.close();
    if (databaseUrl && schema) { const admin = createDatabase(databaseUrl); await admin.executeQuery({ sql: `drop schema ${schema} cascade`, parameters: [], query: {} as never }); await admin.destroy(); }
  });
  it("atomically persists operation steps/events and enqueues Graphile work", async () => {
    const environment = await new EnvironmentService(store).create({ schemaVersion: 1, name: "Database smoke", region: "eu-west-1", network: { cidr: "10.50.0.0/24", lighthouseNodeKeys: ["relay"] }, nodes: [{ key: "relay", name: "Relay", roles: ["lighthouse"], source: { kind: "adopted" } }], deployments: [] });
    const created = await store.createOperation({ environmentId: environment.id, kind: "plan", revision: 1, idempotencyKey: "postgres-operation-0001", steps: [{ key: "validate", title: "Validate" }] });
    expect(created.created).toBe(true); expect(created.operation.steps).toHaveLength(1);
  });
  it("encrypts credentials in PostgreSQL and records fresh worker identity", async () => {
    const credentials = new CredentialService(store, Buffer.alloc(32, 11));
    const created = await credentials.create({ name: "Database secret", kind: "opaque", secret: "postgres-plaintext" });
    expect(await credentials.resolveOpaque(created.id)).toBe("postgres-plaintext");
    const row = (await sql<{ encrypted: string }>`select encode(encrypted_payload,'escape') as encrypted from credentials where id=${created.id}::uuid`.execute(db)).rows[0];
    expect(row?.encrypted).not.toContain("postgres-plaintext");
    await store.heartbeatWorker(randomUUID(), new Date().toISOString(), 3);
    expect(await store.hasFreshWorker(30)).toBe(true);
  });
  it("resets persisted lifecycle fields when a removed node key is re-added", async () => {
    const environments = new EnvironmentService(store);
    const initialSpec = {
      schemaVersion: 1 as const, name: "Node re-add", region: "eu-west-1",
      network: { cidr: "10.51.0.0/24", lighthouseNodeKeys: ["relay"] },
      nodes: [
        { key: "relay", name: "Relay", roles: ["lighthouse"], source: { kind: "adopted" as const } },
        { key: "worker", name: "Worker", roles: ["worker"], source: { kind: "adopted" as const } }
      ], deployments: []
    };
    const environment = await environments.create(initialSpec);
    const worker = (await store.listNodes(environment.id)).find(({ nodeKey }) => nodeKey === "worker")!;
    await store.patchNode(worker.id, { lifecycle: "active", health: "online", lastSeenAt: "2026-01-01T00:00:00.000Z" });

    const withoutWorker = { ...initialSpec, nodes: [initialSpec.nodes[0]!] };
    const removed = await environments.updateSpec(environment.id, environment.etag, withoutWorker);
    expect(await store.getNode(worker.id)).toMatchObject({ lifecycle: "detached", health: "unknown" });

    await environments.updateSpec(environment.id, removed.etag, initialSpec);
    expect(await store.getNode(worker.id)).toMatchObject({ lifecycle: "pending", health: "unknown", lastSeenAt: null });
  });
});
