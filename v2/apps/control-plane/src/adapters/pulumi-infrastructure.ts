import { LocalWorkspace, type EngineEvent, type InlineProgramArgs, type Stack } from "@pulumi/pulumi/automation/index.js";
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { GetResourcesCommand, ResourceGroupsTaggingAPIClient } from "@aws-sdk/client-resource-groups-tagging-api";
import type { EnvironmentSpec, PlanChange } from "@infractory/contracts";
import { digest } from "../domain/spec.js";
import type { ApplyInput, ApplyResult, DestroyResult, InfrastructureAdapter, ProviderObservation } from "./infrastructure.js";

const sensitiveProviderKey = /authorization|cloud.?init|credential|password|private.?key|secret|token|user.?data/i;
const pulumiSecretSignature = "4dabf18193072939515e22adb298388d";

/**
 * Pulumi exports are provider-shaped and may gain new fields as plugins evolve.
 * Redact by key and by Pulumi's secret envelope instead of relying on today's
 * EC2 output shape. The product database only receives this diagnostic view.
 */
export function sanitizeProviderValue(value: unknown, key = ""): unknown {
  if (sensitiveProviderKey.test(key)) return "[REDACTED]";
  if (value === undefined) return null;
  if (Array.isArray(value)) return value.map((item) => sanitizeProviderValue(item));
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (record[pulumiSecretSignature] === "1b47061264138c4ac30d75fd1eb44270") return "[REDACTED]";
    return Object.fromEntries(Object.entries(record).map(([childKey, item]) => [childKey, sanitizeProviderValue(item, childKey)]));
  }
  return value;
}

export function instanceResourceOptions(hasFreshEnrollment: boolean): pulumi.CustomResourceOptions {
  return hasFreshEnrollment
    ? { replaceOnChanges: ["instanceType", "userDataBase64"] }
    : { ignoreChanges: ["userDataBase64"], replaceOnChanges: ["instanceType"] };
}

export function planChangeFromEvent(event: EngineEvent): PlanChange | null {
  const metadata = event.resourcePreEvent?.metadata;
  if (!metadata || metadata.type === "pulumi:pulumi:Stack") return null;
  const action: PlanChange["action"] | null = metadata.op === "same" ? "same"
    : metadata.op === "create" || metadata.op === "import" ? "create"
      : metadata.op === "update" ? "update"
        : metadata.op === "delete" || metadata.op === "discard" || metadata.op === "discard-replaced" || metadata.op === "remove-pending-replace" ? "delete"
          : metadata.op === "replace" || metadata.op === "create-replacement" || metadata.op === "delete-replaced" || metadata.op === "read-replacement" || metadata.op === "import-replacement" ? "replace"
            : null;
  if (!action) return null;
  const resourceKey = metadata.urn.split("::").at(-1) ?? metadata.urn;
  return { action, resourceType: metadata.type, resourceKey, summary: `${action} ${metadata.type} '${resourceKey}'`, destructive: action === "delete" || action === "replace" };
}

export class PulumiInfrastructureAdapter implements InfrastructureAdapter {
  readonly programVersion = "2026.1";
  readonly providerVersion = "7";
  constructor(private readonly backendUrl: string, private readonly publicUrl: string, private readonly agentAmd64Sha256: string) {}

  private args(environmentId: string, spec: EnvironmentSpec, bootstrap: ApplyInput["agentBootstrap"] = {}): InlineProgramArgs {
    const stackName = `environment-${environmentId}`;
    return {
      stackName, projectName: "infractory-environments",
      program: async () => {
        const commonTags = { "managed-by": "infractory", "infractory:environment-id": environmentId, "infractory:program-version": this.programVersion };
        const vpc = new aws.ec2.Vpc("network", { cidrBlock: "10.42.0.0/16", enableDnsHostnames: true, tags: commonTags });
        const gateway = new aws.ec2.InternetGateway("gateway", { vpcId: vpc.id, tags: commonTags });
        const subnet = new aws.ec2.Subnet("public", { vpcId: vpc.id, cidrBlock: "10.42.1.0/24", mapPublicIpOnLaunch: true, availabilityZone: `${spec.region}a`, tags: commonTags });
        const routes = new aws.ec2.RouteTable("public", { vpcId: vpc.id, routes: [{ cidrBlock: "0.0.0.0/0", gatewayId: gateway.id }], tags: commonTags });
        new aws.ec2.RouteTableAssociation("public", { subnetId: subnet.id, routeTableId: routes.id });
        const ami = aws.ssm.getParameterOutput({ name: "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id" });
        const instances: Record<string, pulumi.Output<string>> = {};
        const publicEndpoints: Record<string, pulumi.Output<string>> = {};
        for (const node of spec.nodes) {
          if (node.source.kind !== "aws") continue;
          const ingress = [
            ...(spec.network.lighthouseNodeKeys.includes(node.key) ? [{ protocol: "udp", fromPort: 4242, toPort: 4242, cidrBlocks: ["0.0.0.0/0"], description: "Nebula lighthouse" }] : []),
            ...spec.deployments.filter((item) => item.nodeKey === node.key && item.desiredState === "running").flatMap((item) => item.exposures.map((exposure) => ({ protocol: exposure.protocol, fromPort: exposure.port, toPort: exposure.port, cidrBlocks: exposure.allowedCidrs, description: `Workload ${item.key}` })))
          ];
          const securityGroup = new aws.ec2.SecurityGroup(`node-${node.key}`, { vpcId: vpc.id, ingress, egress: [{ protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"] }], tags: { ...commonTags, "infractory:node-key": node.key } });
          const token = bootstrap[node.key]?.enrollmentToken ?? "preview-token-is-never-applied";
          const url = bootstrap[node.key]?.publicUrl ?? this.publicUrl;
          const tokenB64 = Buffer.from(token).toString("base64"); const urlB64 = Buffer.from(url).toString("base64");
          const artifactUrlB64 = Buffer.from(`${this.publicUrl.replace(/\/$/, "")}/artifacts/infractory-agent-linux-amd64`).toString("base64");
          const configB64 = Buffer.from(JSON.stringify({ controlPlaneUrl: url, stateDir: "/var/lib/infractory", enrollmentTokenFile: "/var/lib/infractory/bootstrap/enrollment-token" })).toString("base64");
          const unitB64 = Buffer.from("[Unit]\nDescription=Infractory node agent\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart=/var/lib/infractory/bin/infractory-agent run --config /etc/infractory-agent/config.json\nRestart=always\nRestartSec=5s\nUser=root\nGroup=root\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\n[Install]\nWantedBy=multi-user.target\n").toString("base64");
          const userData = Buffer.from(`#!/bin/sh\nset -eu\ninstall -d -m 0700 /var/lib/infractory/bootstrap\ninstall -d -m 0755 /var/lib/infractory/bin /etc/infractory-agent\numask 077\nprintf '%s' '${tokenB64}' | base64 -d > /var/lib/infractory/bootstrap/enrollment-token\nprintf '%s' '${configB64}' | base64 -d > /etc/infractory-agent/config.json\nprintf '%s' '${artifactUrlB64}' | base64 -d > /var/lib/infractory/bootstrap/artifact-url\ncurl --proto '=https' --tlsv1.2 --fail --silent --show-error --location "$(cat /var/lib/infractory/bootstrap/artifact-url)" -o /tmp/infractory-agent\necho '${this.agentAmd64Sha256}  /tmp/infractory-agent' | sha256sum -c -\ninstall -o root -g root -m 0755 /tmp/infractory-agent /var/lib/infractory/bin/infractory-agent\nprintf '%s' '${unitB64}' | base64 -d > /etc/systemd/system/infractory-agent.service\nrm -f /tmp/infractory-agent\nsystemctl daemon-reload\nsystemctl enable --now infractory-agent\n`).toString("base64");
          const instance = new aws.ec2.Instance(`node-${node.key}`, { ami: ami.value, instanceType: node.source.instanceType, subnetId: subnet.id, vpcSecurityGroupIds: [securityGroup.id], userDataBase64: pulumi.secret(userData), metadataOptions: { httpTokens: "required", httpEndpoint: "enabled", httpPutResponseHopLimit: 1 }, rootBlockDevice: { volumeType: "gp3", volumeSize: 20, encrypted: true, deleteOnTermination: true }, tags: { ...commonTags, "infractory:node-key": node.key, Name: node.name } }, instanceResourceOptions(Boolean(bootstrap[node.key])));
          instances[node.key] = instance.id;
          if (spec.network.lighthouseNodeKeys.includes(node.key) || node.source.publicEndpoint) publicEndpoints[node.key] = new aws.ec2.Eip(`node-${node.key}`, { instance: instance.id, domain: "vpc", tags: { ...commonTags, "infractory:node-key": node.key } }).publicIp;
        }
        return { vpcId: vpc.id, instances, publicEndpoints };
      }
    };
  }

  private async stack(environmentId: string, spec: EnvironmentSpec, bootstrap?: ApplyInput["agentBootstrap"]): Promise<Stack> {
    process.env.PULUMI_BACKEND_URL = this.backendUrl;
    return LocalWorkspace.createOrSelectStack(this.args(environmentId, spec, bootstrap), { envVars: { AWS_REGION: spec.region, PULUMI_BACKEND_URL: this.backendUrl } });
  }
  async observe(environmentId: string, spec: EnvironmentSpec): Promise<ProviderObservation> {
    const stack = await this.stack(environmentId, spec);
    await stack.refresh({ onOutput: () => undefined });
    const state = await stack.exportStack();
    const resources = state.deployment?.resources?.filter((resource: { type: string }) => resource.type !== "pulumi:pulumi:Stack").map((resource: { urn: string; type: string; outputs?: unknown }) => ({ urn: resource.urn, type: resource.type, name: resource.urn.split("::").at(-1) ?? resource.urn, outputs: sanitizeProviderValue(resource.outputs ?? {}) as Record<string, unknown> })) ?? [];
    const sts = new STSClient({ region: spec.region });
    try { const identity = await sts.send(new GetCallerIdentityCommand({})); if (!identity.Account) throw new Error("AWS STS returned no account ID"); return { accountId: identity.Account, region: spec.region, resources, digest: digest(resources) }; }
    finally { sts.destroy(); }
  }
  async preview(environmentId: string, spec: EnvironmentSpec): Promise<PlanChange[]> {
    const observed = new Map<string, PlanChange>();
    const result = await (await this.stack(environmentId, spec)).preview({
      refresh: true,
      onEvent: (event) => {
        const change = planChangeFromEvent(event); if (!change) return;
        const key = `${change.resourceType}:${change.resourceKey}`; const previous = observed.get(key);
        if (!previous || change.action === "replace" || (change.action === "delete" && previous.action !== "replace")) observed.set(key, change);
      }
    });
    if (observed.size > 0) return [...observed.values()];
    return Object.entries(result.changeSummary).map(([action, count]) => ({ action: action === "create" || action === "update" || action === "replace" || action === "delete" || action === "same" ? action : "update", resourceType: "AWS resources", resourceKey: action, summary: `${count} ${action}`, destructive: action === "delete" || action === "replace" }));
  }
  async apply(input: ApplyInput): Promise<ApplyResult> {
    const result = await (await this.stack(input.environmentId, input.spec, input.agentBootstrap)).up({ onOutput: () => undefined });
    return { outputs: Object.fromEntries(Object.entries(result.outputs).map(([key, value]) => [key, sanitizeProviderValue(value.value, key)])), summary: result.summary.result };
  }
  async destroy(environmentId: string, spec: EnvironmentSpec): Promise<DestroyResult> {
    const stack = await this.stack(environmentId, spec); const result = await stack.destroy({ onOutput: () => undefined });
    return { deleted: Object.values(result.summary.resourceChanges ?? {}).reduce((sum, count) => sum + count, 0), residualResources: [] };
  }
  async auditResiduals(environmentId: string, spec: EnvironmentSpec): Promise<DestroyResult["residualResources"]> {
    const stack = await this.stack(environmentId, spec);
    await stack.refresh({ onOutput: () => undefined });
    const state = await stack.exportStack();
    const resources = state.deployment?.resources?.filter((resource: { type: string }) => resource.type !== "pulumi:pulumi:Stack") ?? [];
    if (resources.length > 0) return resources.map((resource: { type: string; urn: string }) => ({ type: resource.type, id: resource.urn, reason: "Pulumi refresh still observes the resource" }));
    const tagging = new ResourceGroupsTaggingAPIClient({ region: spec.region });
    try {
      const tagged: Array<{ type: string; id: string; reason: string }> = []; let paginationToken: string | undefined;
      do {
        const response = await tagging.send(new GetResourcesCommand({ TagFilters: [{ Key: "managed-by", Values: ["infractory"] }, { Key: "infractory:environment-id", Values: [environmentId] }], ...(paginationToken ? { PaginationToken: paginationToken } : {}) }));
        for (const item of response.ResourceTagMappingList ?? []) if (item.ResourceARN) tagged.push({ type: item.ResourceARN.split(":")[2] ?? "aws", id: item.ResourceARN, reason: "AWS tag audit still observes the resource" });
        paginationToken = response.PaginationToken;
      } while (paginationToken);
      if (tagged.length > 0) return tagged;
    } finally { tagging.destroy(); }
    await stack.workspace.removeStack(stack.name);
    return [];
  }
}
