import { Type, type Static } from "@sinclair/typebox";
import { IsoDateTime, NonEmptyString, Uuid } from "./common.js";

export const OperationKind = Type.Union([
  Type.Literal("plan"), Type.Literal("apply"), Type.Literal("reconcile"), Type.Literal("destroy"), Type.Literal("abandon")
]);
export const OperationState = Type.Union([
  Type.Literal("queued"), Type.Literal("running"), Type.Literal("waiting"), Type.Literal("succeeded"),
  Type.Literal("blocked"), Type.Literal("failed"), Type.Literal("needs_reconciliation"),
  Type.Literal("cancelling"), Type.Literal("cancelled")
]);
export const StepState = Type.Union([
  Type.Literal("pending"), Type.Literal("running"), Type.Literal("waiting"), Type.Literal("succeeded"),
  Type.Literal("failed"), Type.Literal("skipped"), Type.Literal("cancelled")
]);

export const PlanChange = Type.Object({
  action: Type.Union([Type.Literal("create"), Type.Literal("update"), Type.Literal("replace"), Type.Literal("delete"), Type.Literal("same")]),
  resourceType: NonEmptyString,
  resourceKey: NonEmptyString,
  summary: NonEmptyString,
  destructive: Type.Boolean()
});

export const PlanArtifact = Type.Object({
  revision: Type.Integer({ minimum: 1 }),
  revisionDigest: Type.String({ pattern: "^[a-f0-9]{64}$" }),
  accountId: Type.String({ minLength: 1 }),
  region: NonEmptyString,
  providerObservationDigest: Type.String({ pattern: "^[a-f0-9]{64}$" }),
  pulumiProgramVersion: NonEmptyString,
  pulumiProviderVersion: NonEmptyString,
  createdAt: IsoDateTime,
  expiresAt: IsoDateTime,
  changes: Type.Array(PlanChange),
  blockers: Type.Array(Type.String()),
  workloadResolutions: Type.Array(Type.Object({
    deploymentKey: NonEmptyString,
    workloadVersionId: Uuid,
    workloadVersionDigest: Type.String({ pattern: "^[a-f0-9]{64}$" }),
    resolvedImages: Type.Record(Type.String(), Type.String({ pattern: "^.+@sha256:[a-f0-9]{64}$" }))
  }, { additionalProperties: false }))
});

export const OperationStep = Type.Object({
  id: Uuid,
  key: NonEmptyString,
  title: NonEmptyString,
  position: Type.Integer({ minimum: 0 }),
  state: StepState,
  attempt: Type.Integer({ minimum: 0 }),
  startedAt: Type.Union([IsoDateTime, Type.Null()]),
  finishedAt: Type.Union([IsoDateTime, Type.Null()]),
  errorCode: Type.Union([Type.String(), Type.Null()]),
  errorMessage: Type.Union([Type.String(), Type.Null()])
});

export const Operation = Type.Object({
  id: Uuid,
  environmentId: Uuid,
  kind: OperationKind,
  state: OperationState,
  revision: Type.Integer({ minimum: 1 }),
  idempotencyKey: NonEmptyString,
  retryOfOperationId: Type.Union([Uuid, Type.Null()]),
  planOperationId: Type.Union([Uuid, Type.Null()]),
  result: Type.Union([Type.Record(Type.String(), Type.Unknown()), Type.Null()]),
  createdAt: IsoDateTime,
  startedAt: Type.Union([IsoDateTime, Type.Null()]),
  finishedAt: Type.Union([IsoDateTime, Type.Null()]),
  steps: Type.Array(OperationStep)
}, { $id: "Operation" });

export const OperationEvent = Type.Object({
  id: Type.Integer({ minimum: 1 }),
  operationId: Uuid,
  level: Type.Union([Type.Literal("info"), Type.Literal("warning"), Type.Literal("error")]),
  code: NonEmptyString,
  message: NonEmptyString,
  stepKey: Type.Union([Type.String(), Type.Null()]),
  createdAt: IsoDateTime
});

export const PlanEnvironmentRequest = Type.Object({}, { additionalProperties: false });
export const ApplyEnvironmentRequest = Type.Object({ planOperationId: Uuid }, { additionalProperties: false });
export const DestroyEnvironmentRequest = Type.Object({
  confirmName: NonEmptyString,
  acknowledgeResidualRisk: Type.Boolean()
}, { additionalProperties: false });
export const AbandonEnvironmentRequest = Type.Object({ confirmName: NonEmptyString }, { additionalProperties: false });
export const RetryOperationRequest = Type.Object({}, { additionalProperties: false });

export type OperationKind = Static<typeof OperationKind>;
export type OperationState = Static<typeof OperationState>;
export type StepState = Static<typeof StepState>;
export type PlanArtifact = Static<typeof PlanArtifact>;
export type PlanChange = Static<typeof PlanChange>;
export type Operation = Static<typeof Operation>;
export type OperationStep = Static<typeof OperationStep>;
export type OperationEvent = Static<typeof OperationEvent>;
