import { run } from "graphile-worker";
import { buildApp } from "./app.js";
import { randomUUID } from "node:crypto";
import { loadConfig } from "./config.js";

const config = loadConfig();
if (!config.databaseUrl) throw new Error("DATABASE_URL is required for the worker");
const controlPlane = await buildApp({ config });
const instanceId = randomUUID();
const startedAt = new Date().toISOString();
await controlPlane.store.heartbeatWorker(instanceId, startedAt, config.workerConcurrency);
const heartbeat = setInterval(() => {
  void controlPlane.store.heartbeatWorker(instanceId, startedAt, config.workerConcurrency).catch((error: unknown) => {
    controlPlane.app.log.error(error, "worker heartbeat failed");
  });
}, 10_000);
heartbeat.unref();
const runner = await run({
  connectionString: config.databaseUrl,
  concurrency: config.workerConcurrency,
  noHandleSignals: false,
  taskList: {
    advance_operation: async (payload) => {
      const operationId = (payload as { operationId?: unknown }).operationId;
      if (typeof operationId !== "string") throw new Error("advance_operation payload requires operationId");
      await controlPlane.operations.advance(operationId);
    }
  }
});
await runner.promise;
clearInterval(heartbeat);
await controlPlane.app.close();
