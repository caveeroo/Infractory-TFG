import { Type, type Static } from "@sinclair/typebox";

export const Uuid = Type.String({ format: "uuid" });
export const IsoDateTime = Type.String({ format: "date-time" });
export const NonEmptyString = Type.String({ minLength: 1, maxLength: 255 });
export const CursorPageQuery = Type.Object({
  cursor: Type.Optional(Type.String({ maxLength: 512 })),
  limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100, default: 50 }))
});

export const Problem = Type.Object({
  type: Type.String({ format: "uri-reference" }),
  title: NonEmptyString,
  status: Type.Integer({ minimum: 400, maximum: 599 }),
  detail: Type.Optional(Type.String()),
  instance: Type.Optional(Type.String({ format: "uri-reference" })),
  code: Type.Optional(NonEmptyString),
  errors: Type.Optional(Type.Array(Type.Object({ path: Type.String(), message: Type.String() })))
}, { $id: "Problem" });

export type Problem = Static<typeof Problem>;

export const MutationHeaders = Type.Object({
  "idempotency-key": Type.String({ minLength: 8, maxLength: 200 })
});

export const EntityTagHeaders = Type.Object({
  "if-match": Type.String({ pattern: '^"[^"]+"$' })
});
