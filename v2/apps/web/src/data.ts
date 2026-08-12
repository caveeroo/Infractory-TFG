export type StatusTone = "neutral" | "success" | "warning" | "danger" | "info";

export type EnvironmentSummary = {
  id: string;
  name: string;
  description: string;
  lifecycle: "draft" | "applying" | "active" | "apply_failed" | "destroying" | "destroyed" | "destroy_failed" | "abandoned";
  health: "unknown" | "healthy" | "degraded" | "unreachable";
  region: string;
  nodes: number;
  workloads: number;
  observedAt: string;
  expiresAt?: string;
  activeOperation?: { id: string; title: string; step: number; total: number };
};

export type NodeSummary = {
  id: string;
  name: string;
  role: string;
  origin: "AWS managed" | "Adopted";
  health: "online" | "degraded" | "offline";
  overlay: string;
  publicAddress: string;
  observedAt: string;
};

export type WorkloadSummary = {
  id: string;
  name: string;
  version: string;
  node: string;
  health: "healthy" | "degraded" | "stopped";
  endpoint: string;
};

export const demoEnvironments: EnvironmentSummary[] = [
  {
    id: "env-aurora",
    name: "Aurora",
    description: "Primary external assessment · European perimeter",
    lifecycle: "active",
    health: "healthy",
    region: "eu-west-1",
    nodes: 3,
    workloads: 4,
    observedAt: "2026-08-12T08:41:00Z",
    expiresAt: "2026-08-19T18:00:00Z"
  },
  {
    id: "env-osprey",
    name: "Osprey",
    description: "Segmented campaign infrastructure",
    lifecycle: "applying",
    health: "unknown",
    region: "eu-central-1",
    nodes: 4,
    workloads: 5,
    observedAt: "2026-08-12T08:39:00Z",
    activeOperation: { id: "op-1042", title: "Applying environment", step: 5, total: 8 }
  },
  {
    id: "env-cinder",
    name: "Cinder",
    description: "Adopted-host research environment",
    lifecycle: "apply_failed",
    health: "degraded",
    region: "us-east-1",
    nodes: 2,
    workloads: 2,
    observedAt: "2026-08-12T08:14:00Z"
  },
  {
    id: "env-mariner",
    name: "Mariner",
    description: "Awaiting review",
    lifecycle: "draft",
    health: "unknown",
    region: "eu-west-2",
    nodes: 1,
    workloads: 1,
    observedAt: "2026-08-11T16:20:00Z"
  }
];

export const demoNodes: NodeSummary[] = [
  { id: "node-lighthouse", name: "northstar", role: "Lighthouse", origin: "AWS managed", health: "online", overlay: "10.42.0.1", publicAddress: "18.202.41.73", observedAt: "2026-08-12T08:41:12Z" },
  { id: "node-redirector", name: "edge-dub-01", role: "Redirector", origin: "AWS managed", health: "online", overlay: "10.42.0.8", publicAddress: "54.194.21.11", observedAt: "2026-08-12T08:41:06Z" },
  { id: "node-teamserver", name: "operator-core", role: "Team server", origin: "Adopted", health: "degraded", overlay: "10.42.0.12", publicAddress: "Private", observedAt: "2026-08-12T08:38:52Z" }
];

export const demoWorkloads: WorkloadSummary[] = [
  { id: "workload-redirector", name: "HTTP redirector", version: "2.4.1", node: "edge-dub-01", health: "healthy", endpoint: "https://portal.example.test" },
  { id: "workload-teamserver", name: "Team server", version: "1.8.0", node: "operator-core", health: "degraded", endpoint: "10.42.0.12:50050" },
  { id: "workload-telemetry", name: "Telemetry relay", version: "1.2.3", node: "northstar", health: "healthy", endpoint: "Overlay only" },
  { id: "workload-gateway", name: "Operator gateway", version: "1.1.0", node: "northstar", health: "healthy", endpoint: "10.42.0.1:443" }
];

export const operationSteps = [
  { name: "Validate specification", state: "complete", detail: "Revision 7 is valid" },
  { name: "Refresh cloud state", state: "complete", detail: "AWS observation captured" },
  { name: "Apply network", state: "complete", detail: "VPC and routing ready" },
  { name: "Provision nodes", state: "complete", detail: "4 of 4 instances ready" },
  { name: "Enroll nodes", state: "active", detail: "3 of 4 agents connected" },
  { name: "Form private network", state: "pending", detail: "Waiting" },
  { name: "Deploy workloads", state: "pending", detail: "Waiting" },
  { name: "Verify health", state: "pending", detail: "Waiting" }
] as const;

export const activity = [
  { id: "evt-1", title: "Environment reached healthy state", environment: "Aurora", type: "success", at: "2026-08-12T08:41:00Z" },
  { id: "evt-2", title: "Waiting for node enrollment", environment: "Osprey", type: "info", at: "2026-08-12T08:39:12Z" },
  { id: "evt-3", title: "Workload health check failed", environment: "Cinder", type: "danger", at: "2026-08-12T08:14:22Z" },
  { id: "evt-4", title: "Plan created from revision 3", environment: "Mariner", type: "neutral", at: "2026-08-11T16:20:00Z" }
] as const;

export const workloadCatalog = [
  { id: "catalog-redirector", name: "HTTP redirector", description: "Hardened reverse proxy with configurable routing and probes", latest: "2.4.1", versions: 5, updated: "2 days ago", state: "Ready" },
  { id: "catalog-teamserver", name: "Team server", description: "Private command infrastructure pinned to an operator node", latest: "1.8.0", versions: 3, updated: "6 days ago", state: "Ready" },
  { id: "catalog-telemetry", name: "Telemetry relay", description: "Structured operational telemetry over the private network", latest: "1.2.3", versions: 4, updated: "12 days ago", state: "Ready" }
];

export function environmentById(id?: string) {
  return demoEnvironments.find((item) => item.id === id) ?? demoEnvironments[0];
}

export function relativeTime(value: string) {
  const seconds = Math.round((new Date(value).getTime() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, "second");
  if (Math.abs(seconds) < 3600) return formatter.format(Math.round(seconds / 60), "minute");
  if (Math.abs(seconds) < 86400) return formatter.format(Math.round(seconds / 3600), "hour");
  return formatter.format(Math.round(seconds / 86400), "day");
}
