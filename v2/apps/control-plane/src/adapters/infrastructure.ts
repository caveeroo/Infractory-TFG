import type { EnvironmentSpec, PlanChange } from "@infractory/contracts";

export type ProviderObservation = {
  accountId: string;
  region: string;
  digest: string;
  resources: Array<{ urn: string; type: string; name: string; outputs: Record<string, unknown> }>;
};
export type ApplyInput = {
  environmentId: string;
  revision: number;
  spec: EnvironmentSpec;
  agentBootstrap: Record<string, { enrollmentToken: string; publicUrl: string }>;
};
export type ApplyResult = { outputs: Record<string, unknown>; summary: string };
export type DestroyResult = { deleted: number; residualResources: Array<{ type: string; id: string; reason: string }> };

export interface InfrastructureAdapter {
  readonly programVersion: string;
  readonly providerVersion: string;
  observe(environmentId: string, spec: EnvironmentSpec): Promise<ProviderObservation>;
  preview(environmentId: string, spec: EnvironmentSpec, observation: ProviderObservation): Promise<PlanChange[]>;
  apply(input: ApplyInput): Promise<ApplyResult>;
  destroy(environmentId: string, spec: EnvironmentSpec): Promise<DestroyResult>;
  auditResiduals(environmentId: string, spec: EnvironmentSpec): Promise<DestroyResult["residualResources"]>;
}
