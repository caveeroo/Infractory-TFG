import { randomUUID } from "node:crypto";
import YAML from "yaml";
import type { EnvironmentSpec, PlanArtifact, WorkloadManifest, WorkloadPackage, WorkloadVersion } from "@infractory/contracts";
import type { ControlPlaneStore } from "../db/store.js";
import { invalid, notFound } from "../domain/errors.js";
import { digest } from "../domain/spec.js";
import type { CredentialService } from "./credential-service.js";
import { normalizeRegistry } from "./credential-service.js";
import { parseImage, RegistryResolutionError, RegistryService } from "./registry-service.js";

type ComposeService = { image?: string; privileged?: boolean; network_mode?: string; volumes?: Array<string | { source?: string; target?: string; type?: string }>; ports?: Array<string | number | Record<string, unknown>> };
type Resolution = PlanArtifact["workloadResolutions"][number];
export type WorkloadPlan = { blockers: string[]; resolutions: Resolution[] };

export class WorkloadService {
  private readonly registry: RegistryService;
  constructor(private readonly store: ControlPlaneStore, private readonly credentials: CredentialService, registry?: RegistryService) {
    this.registry = registry ?? new RegistryService(credentials);
  }
  async create(name: string, description = ""): Promise<WorkloadPackage> {
    const workload = { id: randomUUID(), name: name.trim(), description: description.trim(), createdAt: new Date().toISOString() };
    await this.store.createWorkload(workload); return workload;
  }
  list(): Promise<WorkloadPackage[]> { return this.store.listWorkloads(); }
  async createVersion(workloadId: string, version: string, composeYaml: string, manifest: WorkloadManifest): Promise<WorkloadVersion> {
    if (!(await this.store.listWorkloads()).some(({ id }) => id === workloadId)) throw notFound("Workload");
    let parsed: { services?: Record<string, ComposeService> };
    try { parsed = YAML.parse(composeYaml) as typeof parsed; } catch { throw invalid("invalid_compose", "Compose YAML could not be parsed"); }
    if (!parsed.services || Object.keys(parsed.services).length === 0) throw invalid("invalid_compose", "Compose must define at least one service");
    for (const [name, service] of Object.entries(parsed.services)) {
      if (!service.image) throw invalid("invalid_compose", `Service '${name}' must declare an OCI image`);
      try { parseImage(service.image); } catch (error) { throw invalid("invalid_compose", error instanceof Error ? error.message : `Service '${name}' has an invalid image`); }
      if (service.privileged) throw invalid("unsafe_compose", `Service '${name}' requests privileged mode`);
      if (service.network_mode === "host") throw invalid("unsafe_compose", `Service '${name}' requests host networking`);
      for (const volume of service.volumes ?? []) {
        const source = typeof volume === "string" ? volume.split(":")[0] : volume.source;
        if (source === "/var/run/docker.sock" || source === "/run/docker.sock") throw invalid("unsafe_compose", `Service '${name}' mounts the Docker socket`);
        if (source?.startsWith("/") && !source.startsWith("/var/lib/infractory/")) throw invalid("unsafe_compose", `Service '${name}' uses an undeclared host path`);
      }
    }
    for (const secret of manifest.secretFiles) if (secret.target.startsWith("/") || secret.target.split("/").includes("..")) throw invalid("unsafe_secret_target", `Secret target '${secret.target}' must be relative and remain within its release`);
    for (const probe of manifest.probes) if (probe.kind === "container" && !parsed.services[probe.target]) throw invalid("invalid_probe", `Container probe targets unknown service '${probe.target}'`);
    const registryNames = new Set<string>();
    for (const binding of manifest.registryCredentials ?? []) {
      const registry = normalizeRegistry(binding.registry); if (registryNames.has(registry)) throw invalid("duplicate_registry_credential", `Registry '${registry}' has more than one credential`); registryNames.add(registry);
    }
    const declared = new Set(manifest.endpoints.map((endpoint) => `${endpoint.port}/${endpoint.protocol === "http" ? "tcp" : endpoint.protocol}`));
    for (const [name, service] of Object.entries(parsed.services)) for (const port of service.ports ?? []) {
      let raw: string;
      if (typeof port === "object") {
        if (port["published"] === undefined) throw invalid("ambiguous_public_port", `Service '${name}' must declare an explicit published port`);
        raw = `${String(port["published"])}/${String(port["protocol"] ?? "tcp")}`;
      } else {
        const [address, protocol = "tcp"] = String(port).split("/"); const segments = address!.split(":");
        if (segments.length > 3) throw invalid("invalid_compose", `Service '${name}' uses an unsupported port syntax`);
        raw = `${segments.length === 1 ? segments[0] : segments.at(-2)}/${protocol}`;
      }
      if (!declared.has(raw)) throw invalid("undeclared_public_port", `Service '${name}' publishes undeclared port ${raw}`);
    }
    const normalized = YAML.stringify(parsed);
    const item: WorkloadVersion = { id: randomUUID(), workloadId, version, digest: digest({ compose: normalized, manifest }), composeYaml: normalized, manifest, createdAt: new Date().toISOString() };
    await this.store.createWorkloadVersion(item); return item;
  }
  listVersions(workloadId: string): Promise<WorkloadVersion[]> { return this.store.listWorkloadVersions(workloadId); }

  async plan(spec: EnvironmentSpec): Promise<WorkloadPlan> {
    const blockers: string[] = []; const resolutions: Resolution[] = [];
    for (const deployment of spec.deployments) {
      const node = spec.nodes.find(({ key }) => key === deployment.nodeKey);
      if (!node) { blockers.push(`Deployment '${deployment.key}' targets a missing node`); continue; }
      if (deployment.desiredState === "stopped") continue;
      const version = await this.store.getWorkloadVersion(deployment.workloadVersionId);
      if (!version) { blockers.push(`Workload version for '${deployment.key}' does not exist`); continue; }
      for (const role of version.manifest.placement.requiredRoles) if (!node.roles.includes(role)) blockers.push(`Deployment '${deployment.key}' requires role '${role}' on node '${node.key}'`);
      for (const secret of version.manifest.secretFiles) {
        const binding = deployment.inputs[secret.input];
        if (!binding || binding.kind !== "secretRef") { blockers.push(`Deployment '${deployment.key}' secret input '${secret.input}' must reference an opaque credential`); continue; }
        const credential = await this.store.getCredential(binding.credentialId);
        if (!credential || credential.kind !== "opaque") blockers.push(`Deployment '${deployment.key}' secret input '${secret.input}' references a missing or incompatible credential`);
      }
      const registryCredentials = new Map<string, string>();
      for (const binding of version.manifest.registryCredentials ?? []) registryCredentials.set(normalizeRegistry(binding.registry), binding.credentialId);
      let parsed: { services?: Record<string, { image?: string }> };
      try { parsed = YAML.parse(version.composeYaml) as typeof parsed; } catch { blockers.push(`Workload version for '${deployment.key}' has invalid stored Compose YAML`); continue; }
      const resolvedImages: Record<string, string> = {}; let resolutionFailed = false;
      for (const [service, value] of Object.entries(parsed.services ?? {})) {
        if (!value.image) { blockers.push(`Service '${deployment.key}/${service}' does not declare an image`); resolutionFailed = true; continue; }
        try {
          const image = parseImage(value.image); const credentialId = registryCredentials.get(image.registry);
          resolvedImages[service] = await this.registry.resolve(value.image, credentialId);
        } catch (error) {
          const message = error instanceof RegistryResolutionError || error instanceof Error ? error.message : "image resolution failed";
          blockers.push(`Image '${deployment.key}/${service}' could not be resolved: ${message}`); resolutionFailed = true;
        }
      }
      if (!resolutionFailed) resolutions.push({ deploymentKey: deployment.key, workloadVersionId: version.id, workloadVersionDigest: version.digest, resolvedImages });
    }
    return { blockers, resolutions };
  }
  async planBlockers(spec: EnvironmentSpec): Promise<string[]> { return (await this.plan(spec)).blockers; }

  async materialize(spec: EnvironmentSpec, environmentId: string, environmentRevision: number, resolutions: Resolution[]): Promise<Array<{ deploymentKey: string; nodeKey: string; desiredState: "running" | "stopped"; payload: Record<string, unknown> }>> {
    const uuid = (key: string): string => {
      const hex = digest(`${environmentId}:${key}`).slice(0, 32).split(""); hex[12] = "5"; hex[16] = ((Number.parseInt(hex[16]!, 16) & 3) | 8).toString(16);
      return `${hex.slice(0, 8).join("")}-${hex.slice(8, 12).join("")}-${hex.slice(12, 16).join("")}-${hex.slice(16, 20).join("")}-${hex.slice(20).join("")}`;
    };
    return Promise.all(spec.deployments.map(async (deployment) => {
      const deploymentId = uuid(deployment.key); const generation = environmentRevision;
      if (deployment.desiredState === "stopped") return {
        deploymentKey: deployment.key,
        nodeKey: deployment.nodeKey,
        desiredState: "stopped" as const,
        payload: { deploymentId, removeOwnedVolumes: false }
      };
      const version = await this.store.getWorkloadVersion(deployment.workloadVersionId); if (!version) throw invalid("workload_plan_stale", `Workload version for '${deployment.key}' no longer exists`);
      const resolution = resolutions.find(({ deploymentKey }) => deploymentKey === deployment.key);
      if (!resolution || resolution.workloadVersionId !== version.id || resolution.workloadVersionDigest !== version.digest) throw invalid("workload_plan_stale", `Reviewed image resolutions for '${deployment.key}' do not match its immutable workload version`);
      const releaseRoot = `/var/lib/infractory/environments/${environmentId}/deployments/${deploymentId}/${generation}`;
      const secretBindings = version.manifest.secretFiles.map((secret) => {
        const binding = deployment.inputs[secret.input];
        if (!binding || binding.kind !== "secretRef") throw invalid("workload_plan_stale", `Secret binding '${secret.input}' changed after planning`);
        return { target: `${releaseRoot}/secrets/${secret.target}`, credentialId: binding.credentialId };
      });
      return {
        deploymentKey: deployment.key, nodeKey: deployment.nodeKey, desiredState: "running" as const,
        payload: {
          environmentId, deploymentId, generation, composeYaml: version.composeYaml, resolvedImages: resolution.resolvedImages,
          secretFiles: [], secretBindings, allowedPorts: deployment.exposures, probes: version.manifest.probes, timeoutSeconds: 600
        }
      };
    }));
  }

  async hydrateTaskPayload(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    const bindings = Array.isArray(payload["secretBindings"]) ? payload["secretBindings"] as Array<{ target?: unknown; credentialId?: unknown }> : [];
    const secretFiles = await Promise.all(bindings.map(async (binding) => {
      if (typeof binding.target !== "string" || typeof binding.credentialId !== "string") throw invalid("invalid_secret_binding", "Stored workload secret binding is invalid");
      return { target: binding.target, contentBase64: Buffer.from(await this.credentials.resolveOpaque(binding.credentialId), "utf8").toString("base64") };
    }));
    const { secretBindings: _removed, ...wire } = payload;
    return { ...wire, secretFiles };
  }
}
