import { Type, type Static } from "@sinclair/typebox";
import { IsoDateTime, NonEmptyString, Uuid } from "./common.js";

export const WorkloadManifest = Type.Object({
  schemaVersion: Type.Literal(1),
  inputsSchema: Type.Record(Type.String(), Type.Unknown()),
  secretFiles: Type.Array(Type.Object({
    input: NonEmptyString,
    target: Type.String({ minLength: 1, maxLength: 512, pattern: "^[A-Za-z0-9][A-Za-z0-9._/-]*$" })
  }, { additionalProperties: false })),
  endpoints: Type.Array(Type.Object({ name: NonEmptyString, protocol: Type.Union([Type.Literal("tcp"), Type.Literal("udp"), Type.Literal("http")]), port: Type.Integer({ minimum: 1, maximum: 65535 }), scope: Type.Union([Type.Literal("public"), Type.Literal("overlay")]) })),
  placement: Type.Object({ requiredRoles: Type.Array(NonEmptyString, { uniqueItems: true }) }),
  probes: Type.Array(Type.Object({ kind: Type.Union([Type.Literal("container"), Type.Literal("http"), Type.Literal("tcp")]), target: NonEmptyString, timeoutSeconds: Type.Integer({ minimum: 1, maximum: 60 }) })),
  registryCredentials: Type.Optional(Type.Array(Type.Object({ registry: Type.String({ minLength: 1, maxLength: 253 }), credentialId: Uuid }, { additionalProperties: false }), { uniqueItems: true, maxItems: 16 }))
}, { additionalProperties: false });

export const WorkloadPackage = Type.Object({ id: Uuid, name: NonEmptyString, description: Type.String(), createdAt: IsoDateTime });
export const WorkloadVersion = Type.Object({
  id: Uuid, workloadId: Uuid, version: Type.String({ pattern: "^[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$" }),
  digest: Type.String({ pattern: "^[a-f0-9]{64}$" }), composeYaml: Type.String(), manifest: WorkloadManifest, createdAt: IsoDateTime
});
export const CreateWorkloadRequest = Type.Object({ name: NonEmptyString, description: Type.Optional(Type.String({ maxLength: 2000 })) }, { additionalProperties: false });
export const CreateWorkloadVersionRequest = Type.Object({ version: Type.String({ pattern: "^[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$" }), composeYaml: Type.String({ minLength: 1, maxLength: 1048576 }), manifest: WorkloadManifest }, { additionalProperties: false });

export type WorkloadManifest = Static<typeof WorkloadManifest>;
export type WorkloadPackage = Static<typeof WorkloadPackage>;
export type WorkloadVersion = Static<typeof WorkloadVersion>;
