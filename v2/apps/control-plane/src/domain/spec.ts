import { createHash } from "node:crypto";
import type { EnvironmentSpec } from "@infractory/contracts";
import { invalid } from "./errors.js";

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, canonical(item)]));
  }
  return value;
}

export function normalizeSpec(spec: EnvironmentSpec): EnvironmentSpec {
  return {
    ...spec,
    name: spec.name.trim(),
    network: { ...spec.network, lighthouseNodeKeys: [...spec.network.lighthouseNodeKeys].sort() },
    nodes: spec.nodes.map((node) => ({ ...node, name: node.name.trim(), roles: [...node.roles].sort() })).sort((a, b) => a.key.localeCompare(b.key)),
    deployments: spec.deployments.map((deployment) => ({
      ...deployment,
      dependsOn: [...deployment.dependsOn].sort(),
      exposures: deployment.exposures.map((exposure) => ({ ...exposure, allowedCidrs: [...exposure.allowedCidrs].sort() }))
        .sort((a, b) => `${a.protocol}:${a.port}`.localeCompare(`${b.protocol}:${b.port}`))
    })).sort((a, b) => a.key.localeCompare(b.key))
  };
}

export function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}

function duplicates(values: string[]): string[] {
  const seen = new Set<string>();
  const duplicate = new Set<string>();
  for (const value of values) seen.has(value) ? duplicate.add(value) : seen.add(value);
  return [...duplicate];
}

export function validateSpec(spec: EnvironmentSpec): void {
  const parseCidr = (cidr: string): number => {
    const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d|[12]\d|3[0-2])$/.exec(cidr);
    if (!match || match.slice(1, 5).some((part) => Number(part) > 255)) throw invalid("invalid_cidr", `'${cidr}' is not an IPv4 CIDR`);
    return Number(match[5]);
  };
  const networkPrefix = parseCidr(spec.network.cidr);
  if (networkPrefix < 16 || networkPrefix > 29) throw invalid("invalid_network_size", "Nebula network prefix must be between /16 and /29");
  if (spec.expiresAt && new Date(spec.expiresAt).getTime() <= Date.now()) throw invalid("invalid_expiry", "Environment expiry must be in the future");
  const nodeKeys = new Set(spec.nodes.map(({ key }) => key));
  const deploymentKeys = new Set(spec.deployments.map(({ key }) => key));
  const duplicateNodes = duplicates(spec.nodes.map(({ key }) => key));
  const duplicateDeployments = duplicates(spec.deployments.map(({ key }) => key));
  if (duplicateNodes.length > 0) throw invalid("duplicate_node_key", `Duplicate node keys: ${duplicateNodes.join(", ")}`);
  if (duplicateDeployments.length > 0) throw invalid("duplicate_deployment_key", `Duplicate deployment keys: ${duplicateDeployments.join(", ")}`);
  for (const lighthouse of spec.network.lighthouseNodeKeys) {
    if (!nodeKeys.has(lighthouse)) throw invalid("unknown_lighthouse", `Lighthouse node '${lighthouse}' does not exist`);
    const node = spec.nodes.find(({ key }) => key === lighthouse);
    if (node?.source.kind === "adopted" && !node.roles.includes("lighthouse")) {
      throw invalid("invalid_adopted_lighthouse", `Adopted lighthouse '${lighthouse}' must have the lighthouse role`);
    }
  }
  for (const deployment of spec.deployments) {
    if (!nodeKeys.has(deployment.nodeKey)) throw invalid("unknown_deployment_node", `Deployment '${deployment.key}' refers to unknown node '${deployment.nodeKey}'`);
    for (const dependency of deployment.dependsOn) {
      if (!deploymentKeys.has(dependency)) throw invalid("unknown_dependency", `Deployment '${deployment.key}' depends on unknown deployment '${dependency}'`);
      if (dependency === deployment.key) throw invalid("cyclic_dependency", `Deployment '${deployment.key}' depends on itself`);
    }
    for (const input of Object.values(deployment.inputs)) {
      if (input.kind === "nodeAddress" && !nodeKeys.has(input.nodeKey)) throw invalid("unknown_input_node", `Input refers to unknown node '${input.nodeKey}'`);
    }
    for (const exposure of deployment.exposures) for (const cidr of exposure.allowedCidrs) parseCidr(cidr);
  }
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const graph = new Map(spec.deployments.map((item) => [item.key, item.dependsOn]));
  const visit = (key: string): void => {
    if (visiting.has(key)) throw invalid("cyclic_dependency", `Deployment dependency cycle includes '${key}'`);
    if (visited.has(key)) return;
    visiting.add(key);
    for (const dependency of graph.get(key) ?? []) visit(dependency);
    visiting.delete(key);
    visited.add(key);
  };
  for (const key of graph.keys()) visit(key);
}
