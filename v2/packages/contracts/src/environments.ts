import { Type, type Static } from "@sinclair/typebox";
import { IsoDateTime, NonEmptyString, Uuid } from "./common.js";

export const InputBinding = Type.Union([
  Type.Object({ kind: Type.Literal("literal"), value: Type.Union([Type.String(), Type.Number(), Type.Boolean()]) }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("secretRef"), credentialId: Uuid }, { additionalProperties: false }),
  Type.Object({
    kind: Type.Literal("nodeAddress"),
    nodeKey: NonEmptyString,
    address: Type.Union([Type.Literal("public"), Type.Literal("private"), Type.Literal("overlay")])
  }, { additionalProperties: false })
]);

export const NodeSpec = Type.Object({
  key: Type.String({ pattern: "^[a-z][a-z0-9-]{0,62}$" }),
  name: NonEmptyString,
  roles: Type.Array(Type.String({ pattern: "^[a-z][a-z0-9-]{0,62}$" }), { uniqueItems: true, maxItems: 32 }),
  source: Type.Union([
    Type.Object({
      kind: Type.Literal("aws"),
      instanceType: NonEmptyString,
      architecture: Type.Literal("amd64"),
      publicEndpoint: Type.Boolean()
    }, { additionalProperties: false }),
    Type.Object({ kind: Type.Literal("adopted") }, { additionalProperties: false })
  ])
}, { additionalProperties: false });

export const DeploymentSpec = Type.Object({
  key: Type.String({ pattern: "^[a-z][a-z0-9-]{0,62}$" }),
  nodeKey: NonEmptyString,
  workloadVersionId: Uuid,
  desiredState: Type.Union([Type.Literal("running"), Type.Literal("stopped")]),
  dependsOn: Type.Array(NonEmptyString, { uniqueItems: true }),
  inputs: Type.Record(Type.String(), InputBinding),
  exposures: Type.Array(Type.Object({
    protocol: Type.Union([Type.Literal("tcp"), Type.Literal("udp")]),
    port: Type.Integer({ minimum: 1, maximum: 65535 }),
    allowedCidrs: Type.Array(Type.String({ minLength: 3, maxLength: 64 }), { minItems: 1, uniqueItems: true })
  }, { additionalProperties: false }))
}, { additionalProperties: false });

export const EnvironmentSpec = Type.Object({
  schemaVersion: Type.Literal(1),
  name: Type.String({ minLength: 2, maxLength: 120 }),
  expiresAt: Type.Optional(IsoDateTime),
  region: Type.String({ pattern: "^[a-z]{2}-[a-z]+-[0-9]+$" }),
  network: Type.Object({
    cidr: Type.String({ minLength: 9, maxLength: 32 }),
    lighthouseNodeKeys: Type.Array(NonEmptyString, { minItems: 1, uniqueItems: true })
  }, { additionalProperties: false }),
  nodes: Type.Array(NodeSpec, { minItems: 1, maxItems: 128 }),
  deployments: Type.Array(DeploymentSpec, { maxItems: 512 })
}, { $id: "EnvironmentSpec", additionalProperties: false });

export const EnvironmentLifecycle = Type.Union([
  Type.Literal("draft"), Type.Literal("applying"), Type.Literal("active"), Type.Literal("apply_failed"),
  Type.Literal("destroying"), Type.Literal("destroyed"), Type.Literal("destroy_failed"), Type.Literal("abandoned")
]);
export const EnvironmentHealth = Type.Union([
  Type.Literal("unknown"), Type.Literal("healthy"), Type.Literal("degraded"), Type.Literal("unreachable")
]);

export const Environment = Type.Object({
  id: Uuid,
  name: NonEmptyString,
  lifecycle: EnvironmentLifecycle,
  health: EnvironmentHealth,
  desiredRevision: Type.Integer({ minimum: 1 }),
  appliedRevision: Type.Union([Type.Integer({ minimum: 1 }), Type.Null()]),
  expiresAt: Type.Union([IsoDateTime, Type.Null()]),
  createdAt: IsoDateTime,
  updatedAt: IsoDateTime,
  etag: NonEmptyString,
  spec: EnvironmentSpec
}, { $id: "Environment" });

export const CreateEnvironmentRequest = Type.Object({ spec: EnvironmentSpec }, { additionalProperties: false });
export const UpdateEnvironmentSpecRequest = Type.Object({ spec: EnvironmentSpec }, { additionalProperties: false });
export const CloneEnvironmentRequest = Type.Object({ name: Type.String({ minLength: 2, maxLength: 120 }) }, { additionalProperties: false });
export const EnvironmentList = Type.Object({ items: Type.Array(Environment), nextCursor: Type.Union([Type.String(), Type.Null()]) });

export type InputBinding = Static<typeof InputBinding>;
export type EnvironmentSpec = Static<typeof EnvironmentSpec>;
export type Environment = Static<typeof Environment>;
export type EnvironmentLifecycle = Static<typeof EnvironmentLifecycle>;
export type EnvironmentHealth = Static<typeof EnvironmentHealth>;
