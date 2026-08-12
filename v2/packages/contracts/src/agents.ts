import { Type, type Static } from "@sinclair/typebox";
import { IsoDateTime, NonEmptyString, Uuid } from "./common.js";

export const AgentCapabilities = Type.Object({
  os: Type.Union([Type.Literal("ubuntu-22.04"), Type.Literal("ubuntu-24.04"), Type.Literal("debian-12")]),
  architecture: Type.Union([Type.Literal("amd64"), Type.Literal("arm64")]),
  dockerVersion: Type.Union([Type.String(), Type.Null()]),
  composeVersion: Type.Union([Type.String(), Type.Null()]),
  tunAvailable: Type.Boolean(),
  ntpSynchronized: Type.Boolean(),
  clockOffsetSeconds: Type.Union([Type.Number(), Type.Null()])
}, { additionalProperties: false });

export const EnrollAgentRequest = Type.Object({
  token: Type.String({ minLength: 32 }),
  publicKey: Type.String({ minLength: 32, maxLength: 8192 }),
  capabilities: AgentCapabilities
}, { additionalProperties: false });
export const EnrollAgentResponse = Type.Object({
  nodeId: Uuid,
  deviceToken: Type.String({ minLength: 32 }),
  expiresAt: IsoDateTime,
  heartbeatIntervalSeconds: Type.Integer({ minimum: 5 })
});
export const HeartbeatRequest = Type.Object({
  generation: Type.Integer({ minimum: 0 }),
  agentVersion: NonEmptyString,
  capabilities: AgentCapabilities,
  observation: Type.Record(Type.String(), Type.Unknown())
}, { additionalProperties: false });
export const RotateDeviceTokenResponse = Type.Object({ deviceToken: Type.String({ minLength: 32 }), expiresAt: IsoDateTime, oldTokenValidUntil: IsoDateTime });

const TaskBase = {
  taskId: Uuid,
  actionKey: NonEmptyString,
  nodeGeneration: Type.Integer({ minimum: 0 }),
  attempt: Type.Integer({ minimum: 1 }),
  leaseToken: Type.String({ minLength: 32 }),
  leaseExpiresAt: IsoDateTime,
  deadline: IsoDateTime
};
const AllowedPort = Type.Object({ protocol: Type.Union([Type.Literal("tcp"), Type.Literal("udp")]), port: Type.Integer({ minimum: 1, maximum: 65535 }), allowedCidrs: Type.Array(NonEmptyString) }, { additionalProperties: false });
const WorkloadProbe = Type.Union([
  Type.Object({ kind: Type.Literal("container"), target: NonEmptyString, timeoutSeconds: Type.Integer({ minimum: 1, maximum: 60 }) }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("http"), target: Type.String({ pattern: "^https?://" }), timeoutSeconds: Type.Integer({ minimum: 1, maximum: 60 }) }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("tcp"), target: Type.String({ pattern: "^[^:]+:[0-9]{1,5}$" }), timeoutSeconds: Type.Integer({ minimum: 1, maximum: 60 }) }, { additionalProperties: false })
]);
export const AgentTask = Type.Union([
  Type.Object({ ...TaskBase, kind: Type.Literal("InspectHost"), payload: Type.Object({}) }),
  Type.Object({ ...TaskBase, kind: Type.Literal("EnsurePrerequisites"), payload: Type.Object({ docker: Type.Boolean(), nebula: Type.Boolean() }) }),
  Type.Object({ ...TaskBase, kind: Type.Literal("EnsureNebula"), payload: Type.Object({ environmentId: Uuid, cidr: NonEmptyString, lighthouse: Type.Boolean(), groups: Type.Array(NonEmptyString, { uniqueItems: true }), certificate: Type.Optional(Type.String()), caCertificate: Type.Optional(Type.String()), config: Type.Optional(Type.String()) }, { additionalProperties: false }) }),
  Type.Object({ ...TaskBase, kind: Type.Literal("ApplyWorkload"), payload: Type.Object({ environmentId: Uuid, deploymentId: Uuid, generation: Type.Integer({ minimum: 1 }), composeYaml: Type.String({ minLength: 1 }), resolvedImages: Type.Record(Type.String(), Type.String()), secretFiles: Type.Array(Type.Object({ target: Type.String(), contentBase64: Type.String() })), allowedPorts: Type.Array(AllowedPort), probes: Type.Array(WorkloadProbe, { maxItems: 32 }), timeoutSeconds: Type.Integer({ minimum: 1, maximum: 900 }) }, { additionalProperties: false }) }),
  Type.Object({ ...TaskBase, kind: Type.Literal("RemoveWorkload"), payload: Type.Object({ deploymentId: Uuid, removeOwnedVolumes: Type.Boolean() }) }),
  Type.Object({ ...TaskBase, kind: Type.Literal("CollectObservation"), payload: Type.Object({ includeWorkloads: Type.Boolean() }, { additionalProperties: false }) }),
  Type.Object({ ...TaskBase, kind: Type.Literal("CleanupNode"), payload: Type.Object({ environmentId: Uuid }) }),
  Type.Object({ ...TaskBase, kind: Type.Literal("TailWorkloadLogs"), payload: Type.Object({ deploymentId: Uuid, since: Type.Optional(IsoDateTime) }) }),
  Type.Object({ ...TaskBase, kind: Type.Literal("RotateDeviceToken"), payload: Type.Object({}, { additionalProperties: false }) }),
  Type.Object({ ...TaskBase, kind: Type.Literal("UpgradeAgent"), payload: Type.Object({ version: NonEmptyString, url: Type.String({ format: "uri" }), sha256: Type.String({ pattern: "^[a-f0-9]{64}$" }) }) })
], { $id: "AgentTask" });
export const TaskEventRequest = Type.Object({
  leaseToken: Type.String({ minLength: 32 }),
  sequence: Type.Integer({ minimum: 0 }),
  level: Type.Union([Type.Literal("info"), Type.Literal("warning"), Type.Literal("error")]),
  message: Type.String({ minLength: 1, maxLength: 8192 })
}, { additionalProperties: false });
export const CompleteTaskRequest = Type.Object({
  leaseToken: Type.String({ minLength: 32 }),
  outcome: Type.Union([Type.Literal("succeeded"), Type.Literal("failed"), Type.Literal("stale")]),
  result: Type.Record(Type.String(), Type.Unknown()),
  errorCode: Type.Optional(NonEmptyString),
  errorMessage: Type.Optional(Type.String({ maxLength: 8192 }))
}, { additionalProperties: false });
export const NebulaCertificateRequest = Type.Object({
  environmentId: Uuid,
  publicKey: Type.String({ minLength: 32, maxLength: 8192 }),
  requestedGroups: Type.Array(NonEmptyString, { uniqueItems: true })
}, { additionalProperties: false });
export const NebulaCertificateResponse = Type.Object({
  certificate: Type.String({ minLength: 32 }),
  caCertificate: Type.String({ minLength: 32 }),
  overlayAddress: NonEmptyString,
  expiresAt: IsoDateTime,
  blocklist: Type.Array(Type.String())
});

export type AgentCapabilities = Static<typeof AgentCapabilities>;
export type AgentTask = Static<typeof AgentTask>;
export type EnrollAgentRequest = Static<typeof EnrollAgentRequest>;
export type HeartbeatRequest = Static<typeof HeartbeatRequest>;
export type TaskEventRequest = Static<typeof TaskEventRequest>;
export type CompleteTaskRequest = Static<typeof CompleteTaskRequest>;
export type NebulaCertificateRequest = Static<typeof NebulaCertificateRequest>;
export type NebulaCertificateResponse = Static<typeof NebulaCertificateResponse>;
