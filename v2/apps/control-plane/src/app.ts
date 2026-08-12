import Fastify, { type FastifyInstance } from "fastify";
import sensible from "@fastify/sensible";
import cors from "@fastify/cors";
import type { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import type { AppConfig } from "./config.js";
import { loadConfig } from "./config.js";
import type { ControlPlaneStore } from "./db/store.js";
import { MemoryStore } from "./db/memory-store.js";
import { PostgresStore } from "./db/postgres-store.js";
import { createDatabase } from "./db/database.js";
import type { InfrastructureAdapter } from "./adapters/infrastructure.js";
import { FakeInfrastructureAdapter } from "./adapters/fake-infrastructure.js";
import { PulumiInfrastructureAdapter } from "./adapters/pulumi-infrastructure.js";
import type { AwsIdentityAdapter } from "./adapters/aws-identity.js";
import { FakeAwsIdentityAdapter, StsAwsIdentityAdapter } from "./adapters/aws-identity.js";
import { DomainError } from "./domain/errors.js";
import { AgentService } from "./services/agent-service.js";
import { EnvironmentService } from "./services/environment-service.js";
import { OperationService } from "./services/operation-service.js";
import { WorkloadService } from "./services/workload-service.js";
import { NetworkService } from "./services/network-service.js";
import { CredentialService } from "./services/credential-service.js";
import { GraphileOperationScheduler, InlineOperationScheduler, type OperationScheduler } from "./services/scheduler.js";
import { registerRoutes } from "./http/routes.js";

export type AppOverrides = { config?: AppConfig; store?: ControlPlaneStore; infrastructure?: InfrastructureAdapter; awsIdentity?: AwsIdentityAdapter; scheduler?: OperationScheduler; workloads?: WorkloadService };
export type ControlPlaneApp = { app: FastifyInstance; store: ControlPlaneStore; operations: OperationService; scheduler: OperationScheduler };

export async function buildApp(overrides: AppOverrides = {}): Promise<ControlPlaneApp> {
  const config = overrides.config ?? loadConfig();
  const store = overrides.store ?? (config.databaseUrl ? new PostgresStore(createDatabase(config.databaseUrl), config.executionMode === "graphile") : new MemoryStore());
  const infrastructure = overrides.infrastructure ?? (config.infrastructureMode === "pulumi" ? new PulumiInfrastructureAdapter(config.pulumiBackendUrl!, config.publicUrl, config.agentAmd64Sha256!) : new FakeInfrastructureAdapter());
  const scheduler = overrides.scheduler ?? (config.executionMode === "graphile" ? new GraphileOperationScheduler(config.databaseUrl!) : new InlineOperationScheduler());
  const environments = new EnvironmentService(store);
  const credentials = new CredentialService(store, config.encryptionKey);
  const workloads = overrides.workloads ?? new WorkloadService(store, credentials);
  const operations = new OperationService(store, infrastructure, scheduler, config, workloads);
  if (scheduler instanceof InlineOperationScheduler) scheduler.bind((id) => operations.advance(id));
  const app = Fastify({ logger: config.executionMode !== "inline", bodyLimit: 2 * 1024 * 1024 }).withTypeProvider<TypeBoxTypeProvider>();
  await app.register(sensible);
  await app.register(cors, { origin: false });
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof DomainError) return reply.code(error.status).type("application/problem+json").send({ type: `https://infractory.dev/problems/${error.code}`, title: error.code.replaceAll("_", " "), status: error.status, detail: error.message, instance: request.url, code: error.code, ...(error.details ? { details: error.details } : {}) });
    if (error instanceof Error && "validation" in error) return reply.code(400).type("application/problem+json").send({ type: "https://infractory.dev/problems/invalid-request", title: "Invalid request", status: 400, detail: error.message, instance: request.url, code: "invalid_request" });
    request.log.error(error); return reply.code(500).type("application/problem+json").send({ type: "https://infractory.dev/problems/internal-error", title: "Internal error", status: 500, detail: "The request could not be completed", instance: request.url, code: "internal_error" });
  });
  await registerRoutes(app, { store, environments, operations, agents: new AgentService(store, config, workloads), workloads, credentials, network: new NetworkService(store, config), awsIdentity: overrides.awsIdentity ?? (config.infrastructureMode === "fake" ? new FakeAwsIdentityAdapter() : new StsAwsIdentityAdapter()), requireWorkerHeartbeat: config.executionMode === "graphile", ...(config.agentArtifactDirectory ? { agentArtifactDirectory: config.agentArtifactDirectory } : {}) });
  app.addHook("onClose", async () => { await scheduler.close(); await store.close(); });
  return { app, store, operations, scheduler };
}
