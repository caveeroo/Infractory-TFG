import { Type, type Static } from "@sinclair/typebox";
import { IsoDateTime, NonEmptyString, Uuid } from "./common.js";

export const CredentialKind = Type.Union([Type.Literal("opaque"), Type.Literal("registry")]);
export const Credential = Type.Object({
  id: Uuid,
  name: NonEmptyString,
  kind: CredentialKind,
  registry: Type.Union([Type.String(), Type.Null()]),
  createdAt: IsoDateTime,
  updatedAt: IsoDateTime
}, { $id: "Credential" });
export const CredentialInput = Type.Union([
  Type.Object({ name: NonEmptyString, kind: Type.Literal("opaque"), secret: Type.String({ minLength: 1, maxLength: 1048576 }) }, { additionalProperties: false }),
  Type.Object({ name: NonEmptyString, kind: Type.Literal("registry"), registry: Type.String({ minLength: 1, maxLength: 253 }), username: Type.Optional(Type.String({ maxLength: 255 })), secret: Type.String({ minLength: 1, maxLength: 16384 }) }, { additionalProperties: false })
]);

export type Credential = Static<typeof Credential>;
export type CredentialInput = Static<typeof CredentialInput>;
export type CredentialKind = Static<typeof CredentialKind>;
