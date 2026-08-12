import type { AgentCapabilities, OperationEvent } from "@infractory/contracts";
import type {
  AgentCommandCreate, AgentCommandRecord, ConnectionRecord, CredentialPublicRecord, CredentialRecord, EnrollmentRecord, EnvironmentRecord, EventInput, IdentityRecord,
  NetworkAuthorityRecord, NetworkMembershipRecord, NodeRecord, ObservationRecord, OperationCreate, OperationPatch, OperationRecord, RevisionRecord, StepPatch,
  WorkloadRecord, WorkloadVersionCreate, WorkloadVersionRecord
} from "../domain/models.js";

export interface ControlPlaneStore {
  createEnvironment(environment: EnvironmentRecord, revision: RevisionRecord, nodes: NodeRecord[]): Promise<void>;
  listEnvironments(limit: number, cursor?: string): Promise<{ items: EnvironmentRecord[]; nextCursor: string | null }>;
  getEnvironment(id: string): Promise<EnvironmentRecord | null>;
  getRevision(environmentId: string, revision?: number): Promise<RevisionRecord | null>;
  updateEnvironment(environment: EnvironmentRecord, revision: RevisionRecord, nodes: NodeRecord[]): Promise<void>;
  patchEnvironment(id: string, patch: Partial<Pick<EnvironmentRecord, "lifecycle" | "health" | "appliedRevision" | "updatedAt">>): Promise<void>;
  createOperation(input: OperationCreate): Promise<{ operation: OperationRecord; created: boolean }>;
  getOperation(id: string): Promise<OperationRecord | null>;
  findActiveOperation(environmentId: string): Promise<OperationRecord | null>;
  patchOperation(id: string, patch: OperationPatch): Promise<void>;
  patchStep(operationId: string, stepId: string, patch: StepPatch): Promise<void>;
  appendOperationEvent(operationId: string, event: EventInput): Promise<OperationEvent>;
  listOperationEvents(operationId: string, after: number, limit: number): Promise<OperationEvent[]>;
  getLatestSuccessfulPlan(environmentId: string, operationId: string): Promise<OperationRecord | null>;
  createEnrollment(enrollment: EnrollmentRecord): Promise<void>;
  consumeEnrollment(tokenHash: string, identity: IdentityRecord): Promise<EnrollmentRecord | null>;
  findIdentityByToken(tokenHash: string): Promise<IdentityRecord | null>;
  rotateIdentity(currentTokenHash: string, identity: IdentityRecord, overlapUntil: string): Promise<void>;
  revokeNodeIdentities(nodeId: string): Promise<void>;
  saveObservation(nodeId: string, observation: ObservationRecord): Promise<void>;
  getObservation(nodeId: string): Promise<ObservationRecord | null>;
  getNode(id: string): Promise<NodeRecord | null>;
  listNodes(environmentId: string): Promise<NodeRecord[]>;
  patchNode(id: string, patch: Partial<NodeRecord>): Promise<void>;
  createAgentCommand(command: AgentCommandCreate): Promise<AgentCommandRecord>;
  listAgentCommands(nodeIds: string[], actionPrefix: string): Promise<AgentCommandRecord[]>;
  expireAgentCommands(nodeIds: string[], actionPrefix: string, now: string): Promise<number>;
  claimAgentCommand(nodeId: string, now: string, leaseExpiresAt: string, leaseTokenHash: string, allowMutating: boolean): Promise<AgentCommandRecord | null>;
  appendAgentCommandEvent(commandId: string, nodeId: string, leaseTokenHash: string, sequence: number, level: "info" | "warning" | "error", message: string): Promise<boolean>;
  completeAgentCommand(commandId: string, nodeId: string, leaseTokenHash: string, outcome: "succeeded" | "failed" | "stale", result: Record<string, unknown>, errorCode?: string, errorMessage?: string): Promise<boolean>;
  createConnection(connection: ConnectionRecord): Promise<void>;
  listConnections(): Promise<ConnectionRecord[]>;
  createWorkload(workload: WorkloadRecord): Promise<void>;
  listWorkloads(): Promise<WorkloadRecord[]>;
  createWorkloadVersion(version: WorkloadVersionRecord): Promise<void>;
  listWorkloadVersions(workloadId: string): Promise<WorkloadVersionRecord[]>;
  getWorkloadVersion(id: string): Promise<WorkloadVersionRecord | null>;
  getNetworkAuthority(environmentId: string): Promise<NetworkAuthorityRecord | null>;
  saveNetworkAuthority(authority: NetworkAuthorityRecord): Promise<void>;
  allocateNetworkMembership(environmentId: string, nodeId: string, cidr: string, publicKey: string): Promise<NetworkMembershipRecord>;
  listNetworkMemberships(environmentId: string): Promise<NetworkMembershipRecord[]>;
  createCredential(credential: CredentialRecord): Promise<void>;
  listCredentials(): Promise<CredentialPublicRecord[]>;
  getCredential(id: string): Promise<CredentialRecord | null>;
  updateCredential(credential: CredentialRecord): Promise<void>;
  deleteCredential(id: string): Promise<boolean>;
  heartbeatWorker(instanceId: string, startedAt: string, concurrency: number): Promise<void>;
  hasFreshWorker(maxAgeSeconds: number): Promise<boolean>;
  ready(): Promise<boolean>;
  close(): Promise<void>;
}

export type AgentObservationInput = { generation: number; agentVersion: string; capabilities: AgentCapabilities; observation: Record<string, unknown> };
