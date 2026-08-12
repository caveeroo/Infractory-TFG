import type {
  AgentCapabilities, AgentTask, AwsConnection, Environment, EnvironmentSpec, Operation, OperationEvent,
  OperationKind, OperationState, OperationStep, PlanArtifact, StepState, WorkloadManifest, WorkloadPackage, WorkloadVersion
} from "@infractory/contracts";

export type RevisionRecord = { id: string; environmentId: string; revision: number; digest: string; spec: EnvironmentSpec; createdAt: string };
export type EnvironmentRecord = Omit<Environment, "spec" | "etag"> & { etag: string };
export type OperationRecord = Omit<Operation, "steps"> & { steps: OperationStep[]; plan: PlanArtifact | null };
export type StepDefinition = { key: string; title: string };
export type OperationCreate = {
  environmentId: string; kind: OperationKind; revision: number; idempotencyKey: string;
  retryOfOperationId?: string; planOperationId?: string; steps: StepDefinition[];
};
export type EnrollmentRecord = { id: string; nodeId: string; tokenHash: string; expiresAt: string; consumedAt: string | null; createdAt: string };
export type IdentityRecord = { id: string; nodeId: string; tokenHash: string; expiresAt: string; revokedAt: string | null; createdAt: string };
export type NodeRecord = {
  id: string; environmentId: string; nodeKey: string; name: string; origin: "aws" | "adopted"; generation: number;
  lifecycle: "pending" | "enrolling" | "active" | "removing" | "removed" | "detached";
  health: "unknown" | "online" | "degraded" | "offline"; lastSeenAt: string | null;
};
export type ObservationRecord = { nodeId: string; generation: number; agentVersion: string; capabilities: AgentCapabilities; observation: Record<string, unknown>; observedAt: string };
export type AgentCommandRecord = {
  id: string; nodeId: string; actionKey: string; nodeGeneration: number; kind: AgentTask["kind"];
  payload: Record<string, unknown>; state: "pending" | "leased" | "succeeded" | "failed" | "stale";
  attempt: number; leaseTokenHash: string | null; leaseExpiresAt: string | null; deadline: string; result: Record<string, unknown> | null;
  errorCode: string | null; errorMessage: string | null;
};
export type AgentCommandCreate = Omit<AgentCommandRecord, "id" | "state" | "attempt" | "leaseTokenHash" | "leaseExpiresAt" | "result" | "errorCode" | "errorMessage">;
export type ConnectionRecord = AwsConnection;
export type WorkloadRecord = WorkloadPackage;
export type WorkloadVersionRecord = WorkloadVersion;
export type EventInput = { level: OperationEvent["level"]; code: string; message: string; stepKey?: string | null };
export type OperationPatch = { state?: OperationState; result?: Record<string, unknown> | null; plan?: PlanArtifact | null; startedAt?: string | null; finishedAt?: string | null };
export type StepPatch = { state: StepState; attempt?: number; startedAt?: string | null; finishedAt?: string | null; errorCode?: string | null; errorMessage?: string | null };
export type WorkloadVersionCreate = { workloadId: string; version: string; digest: string; composeYaml: string; manifest: WorkloadManifest };
export type NetworkAuthorityRecord = { environmentId: string; caCertificate: string; encryptedPrivateKey: string; nonce: string; authTag: string; keyVersion: number; createdAt: string; expiresAt: string };
export type NetworkMembershipRecord = { environmentId: string; nodeId: string; overlayAddress: string; publicKey: string; certificateSerial: string | null; certificateExpiresAt: string | null; status: string };
export type CredentialRecord = { id: string; name: string; kind: "opaque" | "registry"; registry: string | null; encryptedPayload: string; nonce: string; authTag: string; keyVersion: number; createdAt: string; updatedAt: string };
export type CredentialPublicRecord = Omit<CredentialRecord, "encryptedPayload" | "nonce" | "authTag" | "keyVersion">;
