import { randomUUID } from "node:crypto";
import { createReadStream, existsSync } from "node:fs";
import { resolve } from "node:path";
import { Type } from "@sinclair/typebox";
import type { FastifyBaseLogger, FastifyInstance, FastifyReply, FastifyRequest, RawServerDefault } from "fastify";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import {
  AbandonEnvironmentRequest, AgentTask, ApplyEnvironmentRequest, CompleteTaskRequest, CreateAwsConnectionRequest,
  CreateEnvironmentRequest, CreateWorkloadRequest, CreateWorkloadVersionRequest, CursorPageQuery, DestroyEnvironmentRequest,
  EnrollAgentRequest, EnrollAgentResponse, Environment, EnvironmentList, HeartbeatRequest, MutationHeaders, NebulaCertificateRequest, NebulaCertificateResponse,
  Operation, OperationEvent, TaskEventRequest, UpdateEnvironmentSpecRequest, Uuid, WorkloadPackage, WorkloadVersion
  ,Credential, CredentialInput
} from "@infractory/contracts";
import type { AgentService } from "../services/agent-service.js";
import type { EnvironmentService } from "../services/environment-service.js";
import type { OperationService } from "../services/operation-service.js";
import type { WorkloadService } from "../services/workload-service.js";
import type { NetworkService } from "../services/network-service.js";
import type { ControlPlaneStore } from "../db/store.js";
import type { AwsIdentityAdapter } from "../adapters/aws-identity.js";
import type { CredentialService } from "../services/credential-service.js";
import { conflict, notFound } from "../domain/errors.js";

type Dependencies = { store: ControlPlaneStore; environments: EnvironmentService; operations: OperationService; agents: AgentService; workloads: WorkloadService; credentials: CredentialService; network: NetworkService; awsIdentity: AwsIdentityAdapter; requireWorkerHeartbeat: boolean; agentArtifactDirectory?: string };
const IdParams = Type.Object({ id: Uuid });
const NodeParams = Type.Object({ id: Uuid, nodeId: Uuid });
const WorkloadParams = Type.Object({ id: Uuid });
const TaskParams = Type.Object({ id: Uuid });
const idOf = (request: FastifyRequest): string => (request.params as { id: string }).id;
const nodeIdOf = (request: FastifyRequest): string => (request.params as { nodeId: string }).nodeId;
const idempotencyKeyOf = (request: FastifyRequest): string => String(request.headers["idempotency-key"]);

export async function registerRoutes(app: FastifyInstance<RawServerDefault, IncomingMessage, ServerResponse, FastifyBaseLogger, TypeBoxTypeProvider>, deps: Dependencies): Promise<void> {
  app.get("/health/live", async () => ({ status: "ok" }));
  app.get("/health/ready", async (_request, reply) => {
    const schemaReady = await deps.store.ready(); const workerReady = !deps.requireWorkerHeartbeat || await deps.store.hasFreshWorker(30);
    return schemaReady && workerReady ? { status: "ready" } : reply.code(503).send({ status: "not_ready", schemaReady, workerReady });
  });
  const sendArtifact = (name: "infractory-agent-linux-amd64" | "infractory-agent-linux-arm64" | "SHA256SUMS", reply: FastifyReply) => {
    if (!deps.agentArtifactDirectory) throw notFound("Agent artifact");
    const path = resolve(deps.agentArtifactDirectory, name);
    if (!existsSync(path)) throw notFound("Agent artifact");
    return reply.type(name === "SHA256SUMS" ? "text/plain; charset=utf-8" : "application/octet-stream").send(createReadStream(path));
  };
  app.get("/artifacts/infractory-agent-linux-amd64", async (_request, reply) => sendArtifact("infractory-agent-linux-amd64", reply));
  app.get("/artifacts/infractory-agent-linux-arm64", async (_request, reply) => sendArtifact("infractory-agent-linux-arm64", reply));
  app.get("/artifacts/SHA256SUMS", async (_request, reply) => sendArtifact("SHA256SUMS", reply));

  app.get("/api/v1/environments", { schema: { querystring: CursorPageQuery, response: { 200: EnvironmentList } } }, async (request) => deps.environments.list(request.query.limit ?? 50, request.query.cursor));
  app.post("/api/v1/environments", { schema: { body: CreateEnvironmentRequest, response: { 201: Environment } } }, async (request, reply) => reply.code(201).send(await deps.environments.create(request.body.spec)));
  app.get("/api/v1/environments/:id", { schema: { params: IdParams, response: { 200: Environment } } }, async (request, reply) => { const environment = await deps.environments.get(idOf(request)); reply.header("ETag", `"${environment.etag}"`); return environment; });
  app.put("/api/v1/environments/:id/spec", { schema: { params: IdParams, body: UpdateEnvironmentSpecRequest, headers: Type.Object({ "if-match": Type.String() }), response: { 200: Environment } } }, async (request, reply) => { const body = request.body as { spec: import("@infractory/contracts").EnvironmentSpec }; const environment = await deps.environments.updateSpec(idOf(request), String(request.headers["if-match"]), body.spec); reply.header("ETag", `"${environment.etag}"`); return environment; });
  app.post("/api/v1/environments/:id/clone", { schema: { params: IdParams, body: Type.Object({ name: Type.String({ minLength: 2, maxLength: 120 }) }), response: { 201: Environment } } }, async (request, reply) => reply.code(201).send(await deps.environments.clone(idOf(request), (request.body as { name: string }).name)));

  app.post("/api/v1/environments/:id/plan", { schema: { params: IdParams, headers: MutationHeaders, response: { 202: Operation } } }, async (request, reply) => reply.code(202).send(await deps.operations.createPlan(idOf(request), idempotencyKeyOf(request))));
  app.post("/api/v1/environments/:id/apply", { schema: { params: IdParams, headers: MutationHeaders, body: ApplyEnvironmentRequest, response: { 202: Operation } } }, async (request, reply) => reply.code(202).send(await deps.operations.createApply(idOf(request), request.body.planOperationId, idempotencyKeyOf(request))));
  app.post("/api/v1/environments/:id/reconcile", { schema: { params: IdParams, headers: MutationHeaders, response: { 202: Operation } } }, async (request, reply) => reply.code(202).send(await deps.operations.createReconcile(idOf(request), idempotencyKeyOf(request))));
  app.post("/api/v1/environments/:id/destroy", { schema: { params: IdParams, headers: MutationHeaders, body: DestroyEnvironmentRequest, response: { 202: Operation } } }, async (request, reply) => reply.code(202).send(await deps.operations.createDestroy(idOf(request), request.body.confirmName, request.body.acknowledgeResidualRisk, idempotencyKeyOf(request))));
  app.post("/api/v1/environments/:id/abandon", { schema: { params: IdParams, headers: MutationHeaders, body: AbandonEnvironmentRequest, response: { 202: Operation } } }, async (request, reply) => reply.code(202).send(await deps.operations.createAbandon(idOf(request), request.body.confirmName, idempotencyKeyOf(request))));
  app.get("/api/v1/environments/:id/nodes", { schema: { params: IdParams } }, async (request) => ({ items: await deps.environments.listNodes(idOf(request)) }));
  app.get("/api/v1/environments/:id/deployments", { schema: { params: IdParams } }, async (request) => ({ items: (await deps.environments.get(idOf(request))).spec.deployments }));
  app.get("/api/v1/environments/:id/topology", { schema: { params: IdParams } }, async (request) => { const env = await deps.environments.get(idOf(request)); return { nodes: env.spec.nodes, links: env.spec.deployments.flatMap((deployment) => deployment.dependsOn.map((dependency) => ({ from: dependency, to: deployment.key, kind: "depends_on" }))) }; });
  app.post("/api/v1/environments/:id/nodes/:nodeId/enrollment", { schema: { params: NodeParams, headers: MutationHeaders } }, async (request, reply) => reply.code(201).send(await deps.operations.createEnrollment(idOf(request), nodeIdOf(request))));
  app.post("/api/v1/environments/:id/nodes/:nodeId/force-detach", { schema: { params: NodeParams, headers: MutationHeaders } }, async (request, reply) => { await deps.operations.forceDetach(idOf(request), nodeIdOf(request)); return reply.code(204).send(); });

  app.get("/api/v1/operations/:id", { schema: { params: IdParams, response: { 200: Operation } } }, async (request) => { const operation = await deps.store.getOperation(idOf(request)); if (!operation) throw notFound("Operation"); return operation; });
  app.get("/api/v1/operations/:id/events", { schema: { params: IdParams, querystring: Type.Object({ after: Type.Optional(Type.Integer({ minimum: 0 })) }) } }, async (request, reply) => {
    const operation = await deps.store.getOperation(idOf(request)); if (!operation) throw notFound("Operation");
    const accepts = request.headers.accept ?? ""; const queryAfter = (request.query as { after?: number }).after ?? 0; const after = Number.parseInt(String(request.headers["last-event-id"] ?? queryAfter), 10) || 0;
    if (!accepts.includes("text/event-stream")) return { items: await deps.store.listOperationEvents(operation.id, after, 500) };
    reply.hijack(); reply.raw.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive", "X-Accel-Buffering": "no" });
    let cursor = after; const deadline = Date.now() + 25_000; let lastHeartbeat = Date.now();
    while (!reply.raw.destroyed && Date.now() < deadline) {
      const events = await deps.store.listOperationEvents(operation.id, cursor, 100);
      for (const event of events) { cursor = event.id; reply.raw.write(`id: ${event.id}\ndata: ${JSON.stringify(event)}\n\n`); }
      if (Date.now() - lastHeartbeat >= 10_000) { reply.raw.write(": keepalive\n\n"); lastHeartbeat = Date.now(); }
      const current = await deps.store.getOperation(operation.id); if (!current || ["succeeded", "blocked", "failed", "needs_reconciliation", "cancelled"].includes(current.state)) break;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    reply.raw.end();
  });
  app.post("/api/v1/operations/:id/retry", { schema: { params: IdParams, headers: MutationHeaders, response: { 202: Operation } } }, async (request, reply) => reply.code(202).send(await deps.operations.retry(idOf(request), idempotencyKeyOf(request))));
  app.post("/api/v1/operations/:id/cancel", { schema: { params: IdParams, headers: MutationHeaders, response: { 202: Operation } } }, async (request, reply) => reply.code(202).send(await deps.operations.cancel(idOf(request))));

  app.get("/api/v1/workloads", { schema: { response: { 200: Type.Object({ items: Type.Array(WorkloadPackage) }) } } }, async () => ({ items: await deps.workloads.list() }));
  app.post("/api/v1/workloads", { schema: { body: CreateWorkloadRequest, response: { 201: WorkloadPackage } } }, async (request, reply) => reply.code(201).send(await deps.workloads.create(request.body.name, request.body.description)));
  app.post("/api/v1/workloads/:id/versions", { schema: { params: WorkloadParams, body: CreateWorkloadVersionRequest, response: { 201: WorkloadVersion } } }, async (request, reply) => reply.code(201).send(await deps.workloads.createVersion(idOf(request), request.body.version, request.body.composeYaml, request.body.manifest)));
  app.get("/api/v1/workloads/:id/versions", { schema: { params: WorkloadParams } }, async (request) => ({ items: await deps.workloads.listVersions(idOf(request)) }));

  app.get("/api/v1/connections", async () => ({ items: await deps.store.listConnections() }));
  app.post("/api/v1/connections/aws/validate", async () => deps.awsIdentity.validate());
  app.post("/api/v1/connections", { schema: { body: CreateAwsConnectionRequest } }, async (request, reply) => { const identity = await deps.awsIdentity.validate(); const item = { id: randomUUID(), name: request.body.name, ...identity, createdAt: new Date().toISOString() }; await deps.store.createConnection(item); return reply.code(201).send(item); });

  app.get("/api/v1/credentials", { schema: { response: { 200: Type.Object({ items: Type.Array(Credential) }) } } }, async () => ({ items: await deps.credentials.list() }));
  app.post("/api/v1/credentials", { schema: { body: CredentialInput, response: { 201: Credential } } }, async (request, reply) => reply.code(201).send(await deps.credentials.create(request.body)));
  app.get("/api/v1/credentials/:id", { schema: { params: IdParams, response: { 200: Credential } } }, async (request) => deps.credentials.get(idOf(request)));
  app.put("/api/v1/credentials/:id", { schema: { params: IdParams, body: CredentialInput, response: { 200: Credential } } }, async (request) => deps.credentials.update(idOf(request), request.body));
  app.delete("/api/v1/credentials/:id", { schema: { params: IdParams } }, async (request, reply) => { await deps.credentials.delete(idOf(request)); return reply.code(204).send(); });

  app.post("/agent/v1/enroll", { schema: { body: EnrollAgentRequest, response: { 200: EnrollAgentResponse } } }, async (request) => deps.agents.enroll(request.body));
  const auth = async (request: FastifyRequest): Promise<{ nodeId: string; tokenHash: string }> => deps.agents.authenticate(request.headers.authorization);
  app.post("/agent/v1/heartbeat", { schema: { body: HeartbeatRequest } }, async (request, reply) => { const agent = await auth(request); await deps.agents.heartbeat(agent.nodeId, request.body); return reply.code(204).send(); });
  app.get("/agent/v1/tasks/next", { schema: { querystring: Type.Object({ wait: Type.Optional(Type.Integer({ minimum: 0, maximum: 30 })) }) } }, async (request, reply) => { const agent = await auth(request); const task = await deps.agents.nextTask(agent.nodeId, (request.query as { wait?: number }).wait ?? 30); if (!task) return reply.code(204).send(); return reply.send(task); });
  app.post("/agent/v1/tasks/:id/events", { schema: { params: TaskParams, body: TaskEventRequest } }, async (request, reply) => { const agent = await auth(request); await deps.agents.event(agent.nodeId, idOf(request), request.body); return reply.code(204).send(); });
  app.post("/agent/v1/tasks/:id/complete", { schema: { params: TaskParams, body: CompleteTaskRequest } }, async (request, reply) => { const agent = await auth(request); await deps.agents.complete(agent.nodeId, idOf(request), request.body); return reply.code(204).send(); });
  app.post("/agent/v1/device-token/rotate", async (request) => { const agent = await auth(request); return deps.agents.rotate(agent.nodeId, agent.tokenHash); });
  app.post("/agent/v1/nebula-certificate-requests", { schema: { body: NebulaCertificateRequest, response: { 200: NebulaCertificateResponse } } }, async (request) => { const agent = await auth(request); return deps.network.issue(agent.nodeId, request.body); });
}
