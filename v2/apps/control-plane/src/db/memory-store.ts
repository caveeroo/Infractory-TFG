import { randomUUID } from "node:crypto";
import type { OperationEvent } from "@infractory/contracts";
import type {
  AgentCommandCreate, AgentCommandRecord, ConnectionRecord, CredentialPublicRecord, CredentialRecord, EnrollmentRecord, EnvironmentRecord, EventInput, IdentityRecord,
  NetworkAuthorityRecord, NetworkMembershipRecord, NodeRecord, ObservationRecord, OperationCreate, OperationPatch, OperationRecord, RevisionRecord, StepPatch,
  WorkloadRecord, WorkloadVersionRecord
} from "../domain/models.js";
import type { ControlPlaneStore } from "./store.js";

const clone = <T>(value: T): T => structuredClone(value);

export class MemoryStore implements ControlPlaneStore {
  readonly environments = new Map<string, EnvironmentRecord>();
  readonly revisions = new Map<string, RevisionRecord[]>();
  readonly operations = new Map<string, OperationRecord>();
  readonly events = new Map<string, OperationEvent[]>();
  readonly nodes = new Map<string, NodeRecord>();
  readonly enrollments = new Map<string, EnrollmentRecord>();
  readonly identities = new Map<string, IdentityRecord>();
  readonly observations = new Map<string, ObservationRecord>();
  readonly commands = new Map<string, AgentCommandRecord>();
  readonly commandEvents = new Map<string, Array<{ sequence: number; level: string; message: string }>>();
  readonly connections = new Map<string, ConnectionRecord>();
  readonly workloads = new Map<string, WorkloadRecord>();
  readonly workloadVersions = new Map<string, WorkloadVersionRecord[]>();
  readonly authorities = new Map<string, NetworkAuthorityRecord>();
  readonly memberships = new Map<string, NetworkMembershipRecord>();
  readonly credentials = new Map<string, CredentialRecord>();
  readonly workers = new Map<string, { startedAt: string; lastSeenAt: string; concurrency: number }>();

  async createEnvironment(environment: EnvironmentRecord, revision: RevisionRecord, nodes: NodeRecord[]): Promise<void> {
    this.environments.set(environment.id, clone(environment));
    this.revisions.set(environment.id, [clone(revision)]);
    for (const node of nodes) this.nodes.set(node.id, clone(node));
  }

  async listEnvironments(limit: number, cursor?: string): Promise<{ items: EnvironmentRecord[]; nextCursor: string | null }> {
    const all = [...this.environments.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt) || b.id.localeCompare(a.id));
    const offset = cursor ? Math.max(0, Number.parseInt(Buffer.from(cursor, "base64url").toString("utf8"), 10)) : 0;
    const items = all.slice(offset, offset + limit).map(clone);
    return { items, nextCursor: offset + limit < all.length ? Buffer.from(String(offset + limit)).toString("base64url") : null };
  }

  async getEnvironment(id: string): Promise<EnvironmentRecord | null> { return clone(this.environments.get(id) ?? null); }
  async getRevision(environmentId: string, revision?: number): Promise<RevisionRecord | null> {
    const values = this.revisions.get(environmentId) ?? [];
    const found = revision === undefined ? values.at(-1) : values.find((item) => item.revision === revision);
    return clone(found ?? null);
  }

  async updateEnvironment(environment: EnvironmentRecord, revision: RevisionRecord, nodes: NodeRecord[]): Promise<void> {
    this.environments.set(environment.id, clone(environment));
    this.revisions.set(environment.id, [...(this.revisions.get(environment.id) ?? []), clone(revision)]);
    for (const [id, node] of this.nodes) if (node.environmentId === environment.id) this.nodes.delete(id);
    for (const node of nodes) this.nodes.set(node.id, clone(node));
  }
  async patchEnvironment(id: string, patch: Partial<Pick<EnvironmentRecord, "lifecycle" | "health" | "appliedRevision" | "updatedAt">>): Promise<void> {
    const environment = this.environments.get(id); if (environment) Object.assign(environment, clone(patch));
  }

  async createOperation(input: OperationCreate): Promise<{ operation: OperationRecord; created: boolean }> {
    const existing = [...this.operations.values()].find((item) => item.environmentId === input.environmentId && item.idempotencyKey === input.idempotencyKey);
    if (existing) return { operation: clone(existing), created: false };
    const now = new Date().toISOString();
    const operation: OperationRecord = {
      id: randomUUID(), environmentId: input.environmentId, kind: input.kind, state: "queued", revision: input.revision,
      idempotencyKey: input.idempotencyKey, retryOfOperationId: input.retryOfOperationId ?? null, planOperationId: input.planOperationId ?? null, result: null, plan: null,
      createdAt: now, startedAt: null, finishedAt: null,
      steps: input.steps.map((step, position) => ({
        id: randomUUID(), key: step.key, title: step.title, position, state: "pending", attempt: 0,
        startedAt: null, finishedAt: null, errorCode: null, errorMessage: null
      }))
    };
    this.operations.set(operation.id, operation);
    this.events.set(operation.id, []);
    await this.appendOperationEvent(operation.id, { level: "info", code: "operation.queued", message: `${input.kind} operation queued` });
    return { operation: clone(operation), created: true };
  }

  async getOperation(id: string): Promise<OperationRecord | null> { return clone(this.operations.get(id) ?? null); }
  async findActiveOperation(environmentId: string): Promise<OperationRecord | null> {
    const active = new Set(["queued", "running", "waiting", "cancelling"]);
    return clone([...this.operations.values()].find((item) => item.environmentId === environmentId && active.has(item.state)) ?? null);
  }

  async patchOperation(id: string, patch: OperationPatch): Promise<void> {
    const operation = this.operations.get(id);
    if (!operation) return;
    Object.assign(operation, clone(patch));
  }

  async patchStep(operationId: string, stepId: string, patch: StepPatch): Promise<void> {
    const step = this.operations.get(operationId)?.steps.find(({ id }) => id === stepId);
    if (step) Object.assign(step, clone(patch));
  }

  async appendOperationEvent(operationId: string, event: EventInput): Promise<OperationEvent> {
    const events = this.events.get(operationId) ?? [];
    const created: OperationEvent = {
      id: events.length === 0 ? 1 : (events.at(-1)?.id ?? 0) + 1, operationId, level: event.level,
      code: event.code, message: event.message, stepKey: event.stepKey ?? null, createdAt: new Date().toISOString()
    };
    events.push(created);
    this.events.set(operationId, events);
    return clone(created);
  }

  async listOperationEvents(operationId: string, after: number, limit: number): Promise<OperationEvent[]> {
    return clone((this.events.get(operationId) ?? []).filter(({ id }) => id > after).slice(0, limit));
  }

  async getLatestSuccessfulPlan(environmentId: string, operationId: string): Promise<OperationRecord | null> {
    const item = this.operations.get(operationId);
    return clone(item?.environmentId === environmentId && (item.kind === "plan" || item.kind === "reconcile") && item.state === "succeeded" && item.plan ? item : null);
  }

  async createEnrollment(enrollment: EnrollmentRecord): Promise<void> { this.enrollments.set(enrollment.id, clone(enrollment)); }
  async consumeEnrollment(tokenHash: string, identity: IdentityRecord): Promise<EnrollmentRecord | null> {
    const now = new Date().toISOString();
    const enrollment = [...this.enrollments.values()].find((item) => item.tokenHash === tokenHash && item.consumedAt === null && item.expiresAt > now);
    if (!enrollment) return null;
    enrollment.consumedAt = now;
    this.identities.set(identity.id, { ...clone(identity), nodeId: enrollment.nodeId });
    return clone(enrollment);
  }
  async findIdentityByToken(tokenHash: string): Promise<IdentityRecord | null> {
    const now = new Date().toISOString();
    return clone([...this.identities.values()].find((item) => item.tokenHash === tokenHash && item.revokedAt === null && item.expiresAt > now) ?? null);
  }
  async rotateIdentity(currentTokenHash: string, identity: IdentityRecord, overlapUntil: string): Promise<void> {
    const current = [...this.identities.values()].find((item) => item.tokenHash === currentTokenHash && item.revokedAt === null);
    if (!current) throw new Error("Current identity no longer exists");
    current.expiresAt = overlapUntil; this.identities.set(identity.id, { ...clone(identity), nodeId: current.nodeId });
  }
  async revokeNodeIdentities(nodeId: string): Promise<void> { const now = new Date().toISOString(); for (const identity of this.identities.values()) if (identity.nodeId === nodeId) identity.revokedAt = now; }
  async saveObservation(nodeId: string, observation: ObservationRecord): Promise<void> { this.observations.set(nodeId, clone(observation)); const node = this.nodes.get(nodeId); if (node) Object.assign(node, { health: "online", lifecycle: node.lifecycle === "enrolling" ? "active" : node.lifecycle, lastSeenAt: observation.observedAt }); }
  async getObservation(nodeId: string): Promise<ObservationRecord | null> { return clone(this.observations.get(nodeId) ?? null); }
  async getNode(id: string): Promise<NodeRecord | null> { return clone(this.nodes.get(id) ?? null); }
  async listNodes(environmentId: string): Promise<NodeRecord[]> { return clone([...this.nodes.values()].filter((item) => item.environmentId === environmentId)); }
  async patchNode(id: string, patch: Partial<NodeRecord>): Promise<void> { const node = this.nodes.get(id); if (node) Object.assign(node, clone(patch)); }

  async createAgentCommand(input: AgentCommandCreate): Promise<AgentCommandRecord> {
    const existing = [...this.commands.values()].find((item) => item.nodeId === input.nodeId && item.actionKey === input.actionKey);
    if (existing) return clone(existing);
    const command: AgentCommandRecord = { id: randomUUID(), ...clone(input), state: "pending", attempt: 0, leaseTokenHash: null, leaseExpiresAt: null, result: null, errorCode: null, errorMessage: null };
    this.commands.set(command.id, command);
    return clone(command);
  }
  async listAgentCommands(nodeIds: string[], actionPrefix: string): Promise<AgentCommandRecord[]> {
    return clone([...this.commands.values()].filter((item) => nodeIds.includes(item.nodeId) && item.actionKey.startsWith(actionPrefix)));
  }
  async expireAgentCommands(nodeIds: string[], actionPrefix: string, now: string): Promise<number> {
    let expired = 0;
    for (const command of this.commands.values()) if (nodeIds.includes(command.nodeId) && command.actionKey.startsWith(actionPrefix) && command.deadline <= now && (command.state === "pending" || command.state === "leased")) {
      Object.assign(command, { state: "stale", leaseExpiresAt: null, errorCode: "task_deadline_expired", errorMessage: "Agent task was not completed before its deadline" }); expired += 1;
    }
    return expired;
  }

  async claimAgentCommand(nodeId: string, now: string, leaseExpiresAt: string, leaseTokenHash: string, allowMutating: boolean): Promise<AgentCommandRecord | null> {
    const safeKinds = new Set(["InspectHost", "CollectObservation", "TailWorkloadLogs", "RotateDeviceToken"]);
    const command = [...this.commands.values()].find((item) => item.nodeId === nodeId && item.deadline > now && (allowMutating || safeKinds.has(item.kind)) && (item.state === "pending" || (item.state === "leased" && (item.leaseExpiresAt ?? "") < now)));
    if (!command) return null;
    command.state = "leased"; command.leaseExpiresAt = leaseExpiresAt; command.leaseTokenHash = leaseTokenHash; command.attempt += 1;
    return clone(command);
  }
  async appendAgentCommandEvent(commandId: string, nodeId: string, leaseTokenHash: string, sequence: number, level: "info" | "warning" | "error", message: string): Promise<boolean> {
    const command = this.commands.get(commandId);
    if (!command || command.nodeId !== nodeId || command.state !== "leased" || command.leaseTokenHash !== leaseTokenHash || (command.leaseExpiresAt ?? "") <= new Date().toISOString()) return false;
    const events = this.commandEvents.get(commandId) ?? [];
    if (!events.some((event) => event.sequence === sequence)) events.push({ sequence, level, message });
    this.commandEvents.set(commandId, events);
    return true;
  }
  async completeAgentCommand(commandId: string, nodeId: string, leaseTokenHash: string, outcome: "succeeded" | "failed" | "stale", result: Record<string, unknown>, errorCode?: string, errorMessage?: string): Promise<boolean> {
    const command = this.commands.get(commandId);
    if (!command || command.nodeId !== nodeId) return false;
    if (["succeeded", "failed", "stale"].includes(command.state)) return command.state === outcome;
    if (command.state !== "leased" || command.leaseTokenHash !== leaseTokenHash || (command.leaseExpiresAt ?? "") <= new Date().toISOString()) return false;
    command.state = outcome; command.result = clone(result); command.leaseExpiresAt = null;
    command.errorCode = errorCode ?? null; command.errorMessage = errorMessage ?? null;
    return true;
  }

  async createConnection(connection: ConnectionRecord): Promise<void> { this.connections.set(connection.id, clone(connection)); }
  async listConnections(): Promise<ConnectionRecord[]> { return clone([...this.connections.values()]); }
  async createWorkload(workload: WorkloadRecord): Promise<void> { this.workloads.set(workload.id, clone(workload)); }
  async listWorkloads(): Promise<WorkloadRecord[]> { return clone([...this.workloads.values()]); }
  async createWorkloadVersion(version: WorkloadVersionRecord): Promise<void> {
    this.workloadVersions.set(version.workloadId, [...(this.workloadVersions.get(version.workloadId) ?? []), clone(version)]);
  }
  async listWorkloadVersions(workloadId: string): Promise<WorkloadVersionRecord[]> { return clone(this.workloadVersions.get(workloadId) ?? []); }
  async getWorkloadVersion(id: string): Promise<WorkloadVersionRecord | null> { return clone([...this.workloadVersions.values()].flat().find((item) => item.id === id) ?? null); }
  async getNetworkAuthority(environmentId: string): Promise<NetworkAuthorityRecord | null> { return clone(this.authorities.get(environmentId) ?? null); }
  async saveNetworkAuthority(authority: NetworkAuthorityRecord): Promise<void> { if (!this.authorities.has(authority.environmentId)) this.authorities.set(authority.environmentId, clone(authority)); }
  async allocateNetworkMembership(environmentId: string, nodeId: string, cidr: string, publicKey: string): Promise<NetworkMembershipRecord> {
    const existing = this.memberships.get(nodeId); if (existing) return clone(existing);
    const [base, prefix] = cidr.split("/"); const octets = base!.split(".").map(Number); const used = new Set([...this.memberships.values()].filter((item) => item.environmentId === environmentId).map((item) => Number(item.overlayAddress.split(".").at(-1)!.split("/")[0])));
    let host = 2; while (used.has(host)) host += 1; const item = { environmentId, nodeId, overlayAddress: `${octets[0]}.${octets[1]}.${octets[2]}.${host}/${prefix}`, publicKey, certificateSerial: null, certificateExpiresAt: null, status: "allocated" };
    this.memberships.set(nodeId, item); return clone(item);
  }
  async listNetworkMemberships(environmentId: string): Promise<NetworkMembershipRecord[]> { return clone([...this.memberships.values()].filter((item) => item.environmentId === environmentId)); }
  async createCredential(item: CredentialRecord): Promise<void> { if ([...this.credentials.values()].some(({ name }) => name === item.name)) throw new Error("Credential name already exists"); this.credentials.set(item.id, clone(item)); }
  async listCredentials(): Promise<CredentialPublicRecord[]> { return clone([...this.credentials.values()].map(({ encryptedPayload: _, nonce: __, authTag: ___, keyVersion: ____, ...item }) => item)); }
  async getCredential(id: string): Promise<CredentialRecord | null> { return clone(this.credentials.get(id) ?? null); }
  async updateCredential(item: CredentialRecord): Promise<void> { if (!this.credentials.has(item.id)) throw new Error("Credential does not exist"); this.credentials.set(item.id, clone(item)); }
  async deleteCredential(id: string): Promise<boolean> { return this.credentials.delete(id); }
  async heartbeatWorker(instanceId: string, startedAt: string, concurrency: number): Promise<void> { this.workers.set(instanceId, { startedAt, concurrency, lastSeenAt: new Date().toISOString() }); }
  async hasFreshWorker(maxAgeSeconds: number): Promise<boolean> { return [...this.workers.values()].some(({ lastSeenAt }) => Date.now() - new Date(lastSeenAt).getTime() <= maxAgeSeconds * 1000); }
  async ready(): Promise<boolean> { return true; }
  async close(): Promise<void> {}
}
