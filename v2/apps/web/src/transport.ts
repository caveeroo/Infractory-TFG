import {
  Environment as EnvironmentSchema,
  EnvironmentList as EnvironmentListSchema,
  Operation as OperationSchema,
  OperationEvent as OperationEventSchema,
  WorkloadPackage as WorkloadPackageSchema,
  WorkloadVersion as WorkloadVersionSchema,
  AwsConnection as AwsConnectionSchema,
  ValidateAwsConnectionResponse as ValidateAwsConnectionResponseSchema,
  type Environment,
  type EnvironmentSpec,
  type Operation,
  type OperationEvent,
  type WorkloadPackage,
  type WorkloadVersion,
  type WorkloadManifest,
  type AwsConnection
} from "@infractory/contracts";
import { Value } from "@sinclair/typebox/value";
import { FormatRegistry } from "@sinclair/typebox";
import { demoEnvironments } from "./data";

export const demoMode = import.meta.env.VITE_DEMO_MODE === "true";

if (!FormatRegistry.Has("uuid")) FormatRegistry.Set("uuid", (value) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value));
if (!FormatRegistry.Has("date-time")) FormatRegistry.Set("date-time", (value) => !Number.isNaN(Date.parse(value)) && /T/.test(value));

export class ApiError extends Error {
  constructor(message: string, readonly status: number, readonly detail?: string) {
    super(message);
  }
}

let demoSequence = 1;
const demoOperations = new Map<string, Operation>();
function randomId() {
  if (!demoMode) return crypto.randomUUID();
  return `00000000-0000-4000-8000-${String(demoSequence++).padStart(12, "0")}`;
}

function demoEnvironment(spec: EnvironmentSpec): Environment {
  const now = new Date().toISOString();
  return {
    id: randomId(), name: spec.name, lifecycle: "draft", health: "unknown",
    desiredRevision: 1, appliedRevision: null, expiresAt: spec.expiresAt ?? null,
    createdAt: now, updatedAt: now, etag: `W/\"demo-${randomId()}\"`, spec
  };
}

function demoOperation(environmentId: string, kind: Operation["kind"], result: Record<string, unknown> | null = null): Operation {
  const now = new Date().toISOString();
  const operation: Operation = {
    id: randomId(), environmentId, kind, state: kind === "plan" ? "succeeded" : "running",
    revision: 1, idempotencyKey: randomId(), retryOfOperationId: null, planOperationId: kind === "apply" ? randomId() : null, result,
    createdAt: now, startedAt: now, finishedAt: kind === "plan" ? now : null,
    steps: []
  };
  demoOperations.set(operation.id, operation);
  return operation;
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(path, {
    ...init,
    headers: { accept: "application/json", ...(init?.body ? { "content-type": "application/json" } : {}), ...init?.headers }
  });
  const body = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    const problem = body as { title?: string; detail?: string } | null;
    throw new ApiError(problem?.title ?? `Request failed (${response.status})`, response.status, problem?.detail);
  }
  return body;
}

export async function listEnvironments(): Promise<Environment[]> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 160));
    return demoEnvironments.map((item, index) => demoEnvironment({
      schemaVersion: 1, name: item.name, expiresAt: item.expiresAt, region: item.region,
      network: { cidr: `10.${42 + index}.0.0/24`, lighthouseNodeKeys: ["northstar"] },
      nodes: [{ key: "northstar", name: "northstar", roles: ["lighthouse"], source: { kind: "aws", instanceType: "t3.small", architecture: "amd64", publicEndpoint: true } }],
      deployments: []
    })).map((environment, index) => ({ ...environment, id: demoEnvironments[index].id, lifecycle: demoEnvironments[index].lifecycle, health: demoEnvironments[index].health }));
  }
  const body = await request("/api/v1/environments");
  if (!Value.Check(EnvironmentListSchema, body)) throw new ApiError("The control plane returned an invalid environment list", 502);
  return body.items;
}

export async function createEnvironment(spec: EnvironmentSpec): Promise<Environment> {
  if (demoMode) return demoEnvironment(spec);
  const body = await request("/api/v1/environments", { method: "POST", body: JSON.stringify({ spec }) });
  if (!Value.Check(EnvironmentSchema, body)) throw new ApiError("The control plane returned an invalid environment", 502);
  return body;
}

export async function getEnvironment(environmentId: string): Promise<Environment> {
  if (demoMode) {
    const item = (await listEnvironments()).find(({ id }) => id === environmentId);
    if (!item) throw new ApiError("Environment not found", 404);
    return item;
  }
  const body = await request(`/api/v1/environments/${environmentId}`);
  if (!Value.Check(EnvironmentSchema, body)) throw new ApiError("The control plane returned an invalid environment", 502);
  return body;
}

export async function startPlan(environmentId: string): Promise<Operation> {
  if (demoMode) return demoOperation(environmentId, "plan", demoPlanArtifact());
  return mutation(`/api/v1/environments/${environmentId}/plan`, {});
}

export async function startApply(environmentId: string, planOperationId: string): Promise<Operation> {
  if (demoMode) return demoOperation(environmentId, "apply");
  return mutation(`/api/v1/environments/${environmentId}/apply`, { planOperationId });
}

export async function startDestroy(environmentId: string, confirmName: string, acknowledgeResidualRisk: boolean): Promise<Operation> {
  if (demoMode) return demoOperation(environmentId, "destroy");
  return mutation(`/api/v1/environments/${environmentId}/destroy`, { confirmName, acknowledgeResidualRisk });
}

export type NodeRecord = {
  id: string; environmentId: string; nodeKey: string; name: string; origin: "aws" | "adopted";
  generation: number; lifecycle: "pending" | "enrolling" | "active" | "removing" | "removed" | "detached";
  health: "unknown" | "online" | "degraded" | "offline"; lastSeenAt: string | null;
};

export async function listNodes(environmentId: string): Promise<NodeRecord[]> {
  if (demoMode) return [];
  const body = await request(`/api/v1/environments/${environmentId}/nodes`) as { items?: NodeRecord[] };
  if (!body || !Array.isArray(body.items)) throw new ApiError("The control plane returned an invalid node list", 502);
  return body.items;
}

export async function createEnrollment(environmentId: string, nodeId: string): Promise<{ token: string; expiresAt: string }> {
  if (demoMode) return { token: "INFR-2F6M-9QTK-DEMO-TOKEN-NEVER-AUTHENTICATES", expiresAt: new Date(Date.now() + 15 * 60_000).toISOString() };
  const body = await request(`/api/v1/environments/${environmentId}/nodes/${nodeId}/enrollment`, { method: "POST", headers: { "Idempotency-Key": randomId() } }) as { token?: string; expiresAt?: string };
  if (!body?.token || !body.expiresAt) throw new ApiError("The control plane returned invalid enrollment details", 502);
  return { token: body.token, expiresAt: body.expiresAt };
}

export async function listWorkloads(): Promise<WorkloadPackage[]> {
  if (demoMode) return [];
  const body = await request("/api/v1/workloads") as { items?: unknown[] };
  if (!body || !Array.isArray(body.items) || !body.items.every((item) => Value.Check(WorkloadPackageSchema, item))) throw new ApiError("The control plane returned an invalid workload list", 502);
  return body.items as WorkloadPackage[];
}

export async function listWorkloadVersions(workloadId: string): Promise<WorkloadVersion[]> {
  if (demoMode) return [];
  const body = await request(`/api/v1/workloads/${workloadId}/versions`) as { items?: unknown[] };
  if (!body || !Array.isArray(body.items) || !body.items.every((item) => Value.Check(WorkloadVersionSchema, item))) throw new ApiError("The control plane returned invalid workload versions", 502);
  return body.items as WorkloadVersion[];
}

export async function createWorkload(name: string, description: string): Promise<WorkloadPackage> {
  if (demoMode) return { id: randomId(), name, description, createdAt: new Date().toISOString() };
  const body = await request("/api/v1/workloads", { method: "POST", body: JSON.stringify({ name, description }) });
  if (!Value.Check(WorkloadPackageSchema, body)) throw new ApiError("The control plane returned an invalid workload", 502);
  return body;
}

export async function createWorkloadVersion(workloadId: string, version: string, composeYaml: string, manifest: WorkloadManifest): Promise<WorkloadVersion> {
  if (demoMode) return { id: randomId(), workloadId, version, composeYaml, manifest, digest: "b846d923999d165fc6f1417096f931570606aa0e1921af0554ace56c46984a91", createdAt: new Date().toISOString() };
  const body = await request(`/api/v1/workloads/${workloadId}/versions`, { method: "POST", body: JSON.stringify({ version, composeYaml, manifest }) });
  if (!Value.Check(WorkloadVersionSchema, body)) throw new ApiError("The control plane returned an invalid workload version", 502);
  return body;
}

export async function listConnections(): Promise<AwsConnection[]> {
  if (demoMode) return [];
  const body = await request("/api/v1/connections") as { items?: unknown[] };
  if (!body || !Array.isArray(body.items) || !body.items.every((item) => Value.Check(AwsConnectionSchema, item))) throw new ApiError("The control plane returned an invalid connection list", 502);
  return body.items as AwsConnection[];
}

export async function validateAwsConnection(): Promise<{ accountId: string; partition: string; principalArn: string; validatedAt: string }> {
  if (demoMode) return { accountId: "071234567890", partition: "aws", principalArn: "arn:aws:iam::071234567890:role/Infractory", validatedAt: new Date().toISOString() };
  const body = await request("/api/v1/connections/aws/validate", { method: "POST", body: JSON.stringify({}) });
  if (!Value.Check(ValidateAwsConnectionResponseSchema, body)) throw new ApiError("The control plane returned invalid AWS identity metadata", 502);
  return body;
}

export async function createAwsConnection(name: string): Promise<AwsConnection> {
  if (demoMode) return { id: randomId(), name, accountId: "071234567890", partition: "aws", principalArn: "arn:aws:iam::071234567890:role/Infractory", validatedAt: new Date().toISOString(), createdAt: new Date().toISOString() };
  const body = await request("/api/v1/connections", { method: "POST", body: JSON.stringify({ name }) });
  if (!Value.Check(AwsConnectionSchema, body)) throw new ApiError("The control plane returned an invalid connection", 502);
  return body;
}

export async function getOperation(operationId: string): Promise<Operation> {
  if (demoMode) {
    const operation = demoOperations.get(operationId);
    if (!operation) throw new ApiError("Simulated operation not found", 404);
    return operation;
  }
  const body = await request(`/api/v1/operations/${operationId}`);
  if (!Value.Check(OperationSchema, body)) throw new ApiError("The control plane returned an invalid operation", 502);
  return body;
}

async function mutation(path: string, input: unknown): Promise<Operation> {
  const body = await request(path, { method: "POST", headers: { "Idempotency-Key": randomId() }, body: JSON.stringify(input) });
  if (!Value.Check(OperationSchema, body)) throw new ApiError("The control plane returned an invalid operation", 502);
  return body;
}

export function subscribeToOperation(operationId: string, onEvent: (event: OperationEvent) => void, onReconnect: () => void) {
  if (demoMode) return () => undefined;
  let cursor = 0;
  let stream: EventSource | undefined;
  let stopped = false;
  let reconnectTimer: number | undefined;
  const connect = () => {
    if (stopped) return;
    stream = new EventSource(`/api/v1/operations/${operationId}/events?after=${cursor}`);
    const receive = (message: MessageEvent<string>) => {
      const candidate: unknown = JSON.parse(message.data);
      if (!Value.Check(OperationEventSchema, candidate)) return;
      const event = candidate as OperationEvent;
      cursor = Math.max(cursor, event.id);
      onEvent(event);
    };
    stream.onmessage = receive;
    stream.addEventListener("operation-event", receive as EventListener);
    stream.onerror = () => {
      stream?.close();
      if (!stopped) { onReconnect(); reconnectTimer = window.setTimeout(connect, 1500); }
    };
  };
  connect();
  return () => { stopped = true; stream?.close(); if (reconnectTimer) clearTimeout(reconnectTimer); };
}

function demoPlanArtifact() {
  const now = Date.now();
  return {
    revision: 1,
    revisionDigest: "7d2449fa7705cb98799a74dce466f4e3f971c58e2136bc5f3f2bbf18dfb5b318",
    accountId: "071234567890",
    region: "eu-west-1",
    providerObservationDigest: "2d2449fa7705cb98799a74dce466f4e3f971c58e2136bc5f3f2bbf18dfb5b310",
    pulumiProgramVersion: "0.1.0",
    pulumiProviderVersion: "6.70.0",
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 15 * 60_000).toISOString(),
    blockers: [],
    workloadResolutions: [],
    changes: [
      { action: "create", resourceType: "node", resourceKey: "northstar", summary: "Create AWS node · t3.small · public lighthouse", destructive: false },
      { action: "create", resourceType: "node", resourceKey: "edge-01", summary: "Create AWS node · t3.micro · public TCP/443", destructive: false },
      { action: "update", resourceType: "node", resourceKey: "operator-core", summary: "Enroll adopted host and assign overlay address", destructive: false },
      { action: "create", resourceType: "workload", resourceKey: "http-redirector", summary: "Deploy HTTP redirector 2.4.1 on edge-01", destructive: false }
    ]
  };
}
