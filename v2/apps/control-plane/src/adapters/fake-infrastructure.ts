import type { EnvironmentSpec, PlanChange } from "@infractory/contracts";
import { digest } from "../domain/spec.js";
import type { ApplyInput, ApplyResult, DestroyResult, InfrastructureAdapter, ProviderObservation } from "./infrastructure.js";

export class FakeInfrastructureAdapter implements InfrastructureAdapter {
  readonly programVersion = "fake-1";
  readonly providerVersion = "fake-aws-1";
  readonly applied = new Map<string, ApplyInput>();

  async observe(environmentId: string, spec: EnvironmentSpec): Promise<ProviderObservation> {
    const state = this.applied.get(environmentId);
    const resources = state ? state.spec.nodes.flatMap((node) => node.source.kind === "aws" ? [{
      urn: `fake:aws:ec2/instance:${node.key}`, type: "aws:ec2/instance", name: node.name,
      outputs: { state: "running", publicIp: node.source.publicEndpoint ? `203.0.113.${node.key.length + 10}` : null }
    }] : []) : [];
    return { accountId: "000000000000", region: spec.region, resources, digest: digest(resources) };
  }

  async preview(environmentId: string, spec: EnvironmentSpec): Promise<PlanChange[]> {
    const applied = this.applied.get(environmentId);
    if (!applied) return [
      ...spec.nodes.map((node) => ({ action: "create" as const, resourceType: node.source.kind === "aws" ? "AWS node" : "Adopted node", resourceKey: node.key, summary: `Add ${node.name}`, destructive: false })),
      ...spec.deployments.map((deployment) => ({ action: "create" as const, resourceType: "Workload", resourceKey: deployment.key, summary: `Deploy ${deployment.key}`, destructive: false }))
    ];
    return digest(applied.spec) === digest(spec)
      ? [{ action: "same", resourceType: "Environment", resourceKey: environmentId, summary: "No infrastructure changes", destructive: false }]
      : [{ action: "update", resourceType: "Environment", resourceKey: environmentId, summary: "Apply desired revision", destructive: false }];
  }

  async apply(input: ApplyInput): Promise<ApplyResult> {
    this.applied.set(input.environmentId, structuredClone(input));
    return { outputs: { nodeCount: input.spec.nodes.length, managedNodeCount: input.spec.nodes.filter((node) => node.source.kind === "aws").length }, summary: "Fake infrastructure converged" };
  }
  async destroy(environmentId: string): Promise<DestroyResult> { const deleted = this.applied.get(environmentId)?.spec.nodes.filter((node) => node.source.kind === "aws").length ?? 0; this.applied.delete(environmentId); return { deleted, residualResources: [] }; }
  async auditResiduals(environmentId: string): Promise<DestroyResult["residualResources"]> { return this.applied.has(environmentId) ? [{ type: "fake:environment", id: environmentId, reason: "Fake environment remains applied" }] : []; }
}
