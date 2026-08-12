import { afterEach, describe, expect, it } from "vitest";
import type { EnvironmentSpec } from "@infractory/contracts";
import { buildApp, type ControlPlaneApp } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import { MemoryStore } from "../src/db/memory-store.js";
import { FakeInfrastructureAdapter } from "../src/adapters/fake-infrastructure.js";
import type { ApplyInput, ApplyResult, DestroyResult, InfrastructureAdapter, ProviderObservation } from "../src/adapters/infrastructure.js";
import type { OperationScheduler } from "../src/services/scheduler.js";
import { resolve } from "node:path";

const config: AppConfig = {
  host: "127.0.0.1", port: 8080, executionMode: "inline", infrastructureMode: "fake",
  publicUrl: "https://control.test", tokenPepper: "test-pepper-that-is-long-enough-for-tests", encryptionKey: Buffer.alloc(32, 7),
  workerConcurrency: 4, pulumiConcurrency: 2
};
const spec = (name = "Quiet forest"): EnvironmentSpec => ({
  schemaVersion: 1, name, region: "eu-west-1", network: { cidr: "10.80.0.0/24", lighthouseNodeKeys: ["relay"] },
  nodes: [{ key: "relay", name: "Relay", roles: ["lighthouse", "redirector"], source: { kind: "adopted" } }], deployments: []
});
class TestScheduler implements OperationScheduler {
  readonly initialEnqueueIsTransactional = false;
  readonly queued: string[] = [];
  async enqueue(id: string): Promise<void> { this.queued.push(id); }
  async close(): Promise<void> {}
}
const opened: ControlPlaneApp[] = [];
async function setup(infrastructure: InfrastructureAdapter = new FakeInfrastructureAdapter(), appConfig: AppConfig = config) {
  const store = new MemoryStore(); const scheduler = new TestScheduler();
  const result = await buildApp({ config: appConfig, store, scheduler, infrastructure }); opened.push(result);
  return { ...result, store, scheduler };
}
afterEach(async () => { await Promise.all(opened.splice(0).map(({ app }) => app.close())); });

describe("durable environment workflow", () => {
  it("creates immutable revisions and enforces optimistic updates", async () => {
    const { app } = await setup();
    const created = await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: spec() } });
    expect(created.statusCode).toBe(201);
    const environment = created.json();
    const first = await app.inject({ method: "PUT", url: `/api/v1/environments/${environment.id}/spec`, headers: { "if-match": `"${environment.etag}"` }, payload: { spec: spec("Quiet forest II") } });
    expect(first.statusCode).toBe(200); expect(first.json().desiredRevision).toBe(2);
    const stale = await app.inject({ method: "PUT", url: `/api/v1/environments/${environment.id}/spec`, headers: { "if-match": `"${environment.etag}"` }, payload: { spec: spec("Lost update") } });
    expect(stale.statusCode).toBe(409); expect(stale.json().code).toBe("etag_mismatch");
  });

  it("deduplicates mutations and completes a reviewed fake plan/apply", async () => {
    const { app, operations, store } = await setup();
    const environment = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: spec() } })).json();
    const planResponse = await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/plan`, headers: { "idempotency-key": "plan-once-0001" } });
    const duplicate = await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/plan`, headers: { "idempotency-key": "plan-once-0001" } });
    expect(duplicate.json().id).toBe(planResponse.json().id);
    for (let i = 0; i < 3; i += 1) await operations.advance(planResponse.json().id);
    const plan = await store.getOperation(planResponse.json().id); expect(plan?.state).toBe("succeeded"); expect(plan?.plan?.changes[0]?.action).toBe("create");
    const applyResponse = await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/apply`, headers: { "idempotency-key": "apply-once-0001" }, payload: { planOperationId: plan!.id } });
    expect(applyResponse.statusCode).toBe(202);
    for (let i = 0; i < 7; i += 1) await operations.advance(applyResponse.json().id);
    expect((await store.getOperation(applyResponse.json().id))?.state).toBe("succeeded");
    expect((await store.getEnvironment(environment.id))?.lifecycle).toBe("active");
  });

  it("continues using the reviewed artifact after managed infrastructure changes provider state", async () => {
    const { app, operations, store } = await setup();
    const managed = spec("Managed apply");
    managed.nodes = [{ key: "relay", name: "Relay", roles: ["lighthouse"], source: { kind: "aws", instanceType: "t3.small", architecture: "amd64", publicEndpoint: true } }];
    const environment = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: managed } })).json();
    const plan = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/plan`, headers: { "idempotency-key": "plan-managed-0001" } })).json();
    for (let turn = 0; turn < 3; turn += 1) await operations.advance(plan.id);
    const apply = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/apply`, headers: { "idempotency-key": "apply-managed-0001" }, payload: { planOperationId: plan.id } })).json();
    for (let turn = 0; turn < 7; turn += 1) await operations.advance(apply.id);
    expect((await store.getOperation(apply.id))?.state).toBe("succeeded");
    expect((await store.getEnvironment(environment.id))?.lifecycle).toBe("active");
  });

  it("advances node generations only when node or network intent changes", async () => {
    const { app, store } = await setup();
    const created = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: spec() } })).json();
    expect((await store.listNodes(created.id))[0]?.generation).toBe(0);

    const renamedEnvironment = spec("Renamed environment");
    const renamed = await app.inject({ method: "PUT", url: `/api/v1/environments/${created.id}/spec`, headers: { "if-match": `"${created.etag}"` }, payload: { spec: renamedEnvironment } });
    expect((await store.listNodes(created.id))[0]?.generation).toBe(0);

    const changedRole = spec("Renamed environment"); changedRole.nodes[0]!.roles = ["lighthouse"];
    const roleUpdate = await app.inject({ method: "PUT", url: `/api/v1/environments/${created.id}/spec`, headers: { "if-match": `"${renamed.json().etag}"` }, payload: { spec: changedRole } });
    expect((await store.listNodes(created.id))[0]?.generation).toBe(1);

    const changedNetwork = structuredClone(changedRole); changedNetwork.network.cidr = "10.81.0.0/24";
    await app.inject({ method: "PUT", url: `/api/v1/environments/${created.id}/spec`, headers: { "if-match": `"${roleUpdate.json().etag}"` }, payload: { spec: changedNetwork } });
    expect((await store.listNodes(created.id))[0]?.generation).toBe(2);
  });

  it("dispatches prerequisite installation before Nebula configuration", async () => {
    const liveLikeConfig: AppConfig = { ...config, infrastructureMode: "pulumi" };
    const { app, operations, store } = await setup(new FakeInfrastructureAdapter(), liveLikeConfig);
    const managed = spec("Managed prerequisites");
    managed.nodes = [{ key: "relay", name: "Relay", roles: ["lighthouse"], source: { kind: "aws", instanceType: "t3.small", architecture: "amd64", publicEndpoint: true } }];
    const environment = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: managed } })).json();
    const plan = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/plan`, headers: { "idempotency-key": "plan-prerequisites-0001" } })).json();
    for (let turn = 0; turn < 3; turn += 1) await operations.advance(plan.id);
    const apply = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/apply`, headers: { "idempotency-key": "apply-prerequisites-0001" }, payload: { planOperationId: plan.id } })).json();
    await operations.advance(apply.id); await operations.advance(apply.id);
    const node = (await store.listNodes(environment.id))[0]!; await store.patchNode(node.id, { lifecycle: "active", health: "online" });
    await operations.advance(apply.id); await operations.advance(apply.id);
    const operation = await store.getOperation(apply.id);
    expect(operation?.steps.map(({ key }) => key)).toEqual(["verify_plan", "apply_infrastructure", "await_nodes", "prepare_nodes", "configure_network", "deploy_workloads", "verify_health"]);
    expect([...store.commands.values()][0]).toMatchObject({ kind: "EnsurePrerequisites", payload: { docker: true, nebula: true } });
    expect(operation?.steps.find(({ key }) => key === "prepare_nodes")?.state).toBe("waiting");
    expect(operation?.steps.find(({ key }) => key === "configure_network")?.state).toBe("pending");
  });

  it("mints managed enrollment only for new or replacement instances", async () => {
    class CapturingAdapter extends FakeInfrastructureAdapter { readonly inputs: ApplyInput[] = []; override async apply(input: ApplyInput): Promise<ApplyResult> { this.inputs.push(structuredClone(input)); return super.apply(input); } }
    const adapter = new CapturingAdapter(); const { app, operations, store } = await setup(adapter);
    const managed = spec("Selective bootstrap"); managed.nodes = [{ key: "relay", name: "Relay", roles: ["lighthouse"], source: { kind: "aws", instanceType: "t3.small", architecture: "amd64", publicEndpoint: true } }];
    const environment = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: managed } })).json();

    const apply = async (suffix: string): Promise<void> => {
      const plan = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/plan`, headers: { "idempotency-key": `plan-bootstrap-${suffix}` } })).json();
      for (let turn = 0; turn < 3; turn += 1) await operations.advance(plan.id);
      const operation = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/apply`, headers: { "idempotency-key": `apply-bootstrap-${suffix}` }, payload: { planOperationId: plan.id } })).json();
      for (let turn = 0; turn < 7; turn += 1) await operations.advance(operation.id);
      expect((await store.getOperation(operation.id))?.state).toBe("succeeded");
    };

    await apply("initial-0001"); expect(adapter.inputs[0]?.agentBootstrap).toHaveProperty("relay");
    await apply("unchanged-0001"); expect(adapter.inputs[1]?.agentBootstrap).toEqual({});

    const current = await app.inject({ method: "GET", url: `/api/v1/environments/${environment.id}` });
    const replacement = structuredClone(current.json().spec) as EnvironmentSpec;
    const source = replacement.nodes[0]!.source; if (source.kind !== "aws") throw new Error("expected managed node"); source.instanceType = "t3.medium";
    await app.inject({ method: "PUT", url: `/api/v1/environments/${environment.id}/spec`, headers: { "if-match": `"${current.json().etag}"` }, payload: { spec: replacement } });
    await apply("replacement-0001"); expect(adapter.inputs[2]?.agentBootstrap).toHaveProperty("relay");
  });

  it("rejects a stale reviewed plan", async () => {
    const { app, operations, store } = await setup();
    const environment = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: spec() } })).json();
    const plan = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/plan`, headers: { "idempotency-key": "plan-stale-0001" } })).json();
    for (let i = 0; i < 3; i += 1) await operations.advance(plan.id);
    const current = await store.getEnvironment(environment.id);
    await app.inject({ method: "PUT", url: `/api/v1/environments/${environment.id}/spec`, headers: { "if-match": `"${current!.etag}"` }, payload: { spec: spec("Changed after plan") } });
    const apply = await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/apply`, headers: { "idempotency-key": "apply-stale-0001" }, payload: { planOperationId: plan.id } });
    expect(apply.statusCode).toBe(409); expect(apply.json().code).toBe("stale_plan");
  });

  it("reports an ambiguous provider mutation as reconciliation required", async () => {
    class FailingAdapter extends FakeInfrastructureAdapter {
      override async apply(_input: ApplyInput): Promise<ApplyResult> { throw new Error("provider connection dropped"); }
    }
    const { app, operations, store } = await setup(new FailingAdapter());
    const environment = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: spec() } })).json();
    const plan = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/plan`, headers: { "idempotency-key": "plan-fail-0001" } })).json();
    for (let i = 0; i < 3; i += 1) await operations.advance(plan.id);
    const apply = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/apply`, headers: { "idempotency-key": "apply-fail-0001" }, payload: { planOperationId: plan.id } })).json();
    await operations.advance(apply.id); await operations.advance(apply.id);
    expect((await store.getOperation(apply.id))?.state).toBe("needs_reconciliation");
    expect((await store.getEnvironment(environment.id))?.lifecycle).toBe("apply_failed");
  });

  it("fences an interrupted provider mutation instead of executing it again", async () => {
    class CountingAdapter extends FakeInfrastructureAdapter {
      calls = 0;
      override async apply(input: ApplyInput): Promise<ApplyResult> { this.calls += 1; return super.apply(input); }
    }
    const adapter = new CountingAdapter(); const { app, operations, store } = await setup(adapter);
    const environment = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: spec() } })).json();
    const plan = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/plan`, headers: { "idempotency-key": "plan-fence-0001" } })).json();
    for (let i = 0; i < 3; i += 1) await operations.advance(plan.id);
    const apply = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/apply`, headers: { "idempotency-key": "apply-fence-0001" }, payload: { planOperationId: plan.id } })).json();
    await operations.advance(apply.id);
    const operation = await store.getOperation(apply.id); const mutation = operation!.steps.find(({ key }) => key === "apply_infrastructure")!;
    await store.patchStep(operation!.id, mutation.id, { state: "running", attempt: 1, startedAt: new Date().toISOString() });
    await store.patchOperation(operation!.id, { state: "running" });
    await operations.advance(operation!.id);
    expect(adapter.calls).toBe(0); expect((await store.getOperation(operation!.id))?.state).toBe("needs_reconciliation");
  });

  it("rejects a reviewed plan when AWS account identity changes", async () => {
    class SwitchingIdentityAdapter extends FakeInfrastructureAdapter {
      accountId = "111111111111";
      override async observe(environmentId: string, environmentSpec: EnvironmentSpec): Promise<ProviderObservation> {
        return { ...(await super.observe(environmentId, environmentSpec)), accountId: this.accountId };
      }
    }
    const adapter = new SwitchingIdentityAdapter(); const { app, operations } = await setup(adapter);
    const environment = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: spec() } })).json();
    const plan = (await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/plan`, headers: { "idempotency-key": "plan-account-0001" } })).json();
    for (let i = 0; i < 3; i += 1) await operations.advance(plan.id);
    adapter.accountId = "222222222222";
    const apply = await app.inject({ method: "POST", url: `/api/v1/environments/${environment.id}/apply`, headers: { "idempotency-key": "apply-account-0001" }, payload: { planOperationId: plan.id } });
    expect(apply.statusCode).toBe(409); expect(apply.json().code).toBe("provider_identity_changed");
  });
});

describe("credential custody", () => {
  it("exposes metadata-only CRUD and decrypts only through the internal service", async () => {
    const { app, store } = await setup();
    const created = await app.inject({ method: "POST", url: "/api/v1/credentials", payload: { name: "API token", kind: "opaque", secret: "never-return-this" } });
    expect(created.statusCode).toBe(201); expect(created.body).not.toContain("never-return-this"); expect(created.json().secret).toBeUndefined();
    const id = created.json().id; const stored = store.credentials.get(id)!;
    expect(JSON.stringify(stored)).not.toContain("never-return-this");
    expect((await app.inject({ method: "GET", url: `/api/v1/credentials/${id}` })).body).not.toContain("never-return-this");
    const updated = await app.inject({ method: "PUT", url: `/api/v1/credentials/${id}`, payload: { name: "API token", kind: "opaque", secret: "replacement-value" } });
    expect(updated.statusCode).toBe(200); expect(updated.body).not.toContain("replacement-value");
    const service = new (await import("../src/services/credential-service.js")).CredentialService(store, config.encryptionKey);
    expect(await service.resolveOpaque(id)).toBe("replacement-value");
    expect((await app.inject({ method: "DELETE", url: `/api/v1/credentials/${id}` })).statusCode).toBe(204);
  });
});

describe("agent trust lifecycle", () => {
  const capabilities = { os: "ubuntu-24.04" as const, architecture: "amd64" as const, dockerVersion: "27", composeVersion: "2.29", tunAvailable: true, ntpSynchronized: true, clockOffsetSeconds: 0 };
  it("consumes enrollment once, rotates with overlap, and revokes on detach", async () => {
    const { app, store, operations } = await setup();
    const environment = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: spec() } })).json();
    const node = (await store.listNodes(environment.id))[0]!; const enrollment = await operations.createEnrollment(environment.id, node.id);
    const body = { token: enrollment.token, publicKey: "A".repeat(64), capabilities };
    const enrolled = await app.inject({ method: "POST", url: "/agent/v1/enroll", payload: body });
    expect(enrolled.statusCode).toBe(200);
    expect((await app.inject({ method: "POST", url: "/agent/v1/enroll", payload: body })).statusCode).toBe(401);
    const original = enrolled.json().deviceToken;
    const heartbeat = await app.inject({ method: "POST", url: "/agent/v1/heartbeat", headers: { authorization: `Bearer ${original}` }, payload: { generation: 0, agentVersion: "0.1.0", capabilities, observation: {} } });
    expect(heartbeat.statusCode).toBe(204);
    const rotated = await app.inject({ method: "POST", url: "/agent/v1/device-token/rotate", headers: { authorization: `Bearer ${original}` } });
    expect(rotated.statusCode).toBe(200);
    expect((await app.inject({ method: "POST", url: "/agent/v1/heartbeat", headers: { authorization: `Bearer ${rotated.json().deviceToken}` }, payload: { generation: 0, agentVersion: "0.1.0", capabilities, observation: {} } })).statusCode).toBe(204);
    await operations.forceDetach(environment.id, node.id);
    expect((await app.inject({ method: "POST", url: "/agent/v1/heartbeat", headers: { authorization: `Bearer ${rotated.json().deviceToken}` }, payload: { generation: 0, agentVersion: "0.1.0", capabilities, observation: {} } })).statusCode).toBe(401);
  });

  it("does not leave stale observations green", async () => {
    const { app, store } = await setup();
    const environment = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: spec() } })).json();
    const node = (await store.listNodes(environment.id))[0]!;
    await store.patchEnvironment(environment.id, { health: "healthy" });
    await store.patchNode(node.id, { health: "online", lastSeenAt: new Date(Date.now() - 61_000).toISOString() });
    const response = await app.inject({ method: "GET", url: `/api/v1/environments/${environment.id}` });
    expect(response.json().health).toBe("unreachable");
  });

  it("expires undelivered commands to a truthful stale outcome", async () => {
    const { app, store } = await setup();
    const environment = (await app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: spec() } })).json();
    const node = (await store.listNodes(environment.id))[0]!;
    const command = await store.createAgentCommand({ nodeId: node.id, actionKey: "expiry:1", nodeGeneration: node.generation, kind: "CleanupNode", payload: { environmentId: environment.id }, deadline: new Date(Date.now() - 1_000).toISOString() });
    expect(await store.expireAgentCommands([node.id], "expiry:", new Date().toISOString())).toBe(1);
    expect((await store.listAgentCommands([node.id], "expiry:"))[0]).toMatchObject({ id: command.id, state: "stale", errorCode: "task_deadline_expired" });
  });
});

describe("Nebula authority", () => {
  it("encrypts CA private material and issues node-scoped certificates through stdin helper", async () => {
    const helperConfig = { ...config, pkiHelperPath: resolve(import.meta.dirname, "fixtures/fake-pki") };
    const store = new MemoryStore(); const scheduler = new TestScheduler(); const control = await buildApp({ config: helperConfig, store, scheduler, infrastructure: new FakeInfrastructureAdapter() }); opened.push(control);
    const environment = (await control.app.inject({ method: "POST", url: "/api/v1/environments", payload: { spec: spec() } })).json();
    const network = new (await import("../src/services/network-service.js")).NetworkService(store, helperConfig);
    await network.ensureAuthority(environment.id, environment.spec);
    const authority = await store.getNetworkAuthority(environment.id);
    expect(authority?.encryptedPrivateKey).not.toContain("FAKE PRIVATE KEY");
    const node = (await store.listNodes(environment.id))[0]!;
    const response = await network.issue(node.id, { environmentId: environment.id, publicKey: "FAKE PUBLIC KEY".repeat(4), requestedGroups: ["lighthouse", "unauthorized"] });
    expect(response).toMatchObject({ certificate: "FAKE HOST CERTIFICATE", caCertificate: "FAKE CA CERTIFICATE" });
    expect(response.overlayAddress).toMatch(/^10\.80\.0\.2\/24$/);
  });
});

describe("workload admission", () => {
  it("rejects privileged, Docker socket, and undeclared port access", async () => {
    const { app } = await setup();
    const workload = (await app.inject({ method: "POST", url: "/api/v1/workloads", payload: { name: "relay" } })).json();
    const manifest = { schemaVersion: 1, inputsSchema: {}, secretFiles: [], endpoints: [], placement: { requiredRoles: [] }, probes: [] };
    for (const composeYaml of [
      "services:\n  relay:\n    image: nginx\n    privileged: true\n",
      "services:\n  relay:\n    image: nginx\n    volumes: [/run/docker.sock:/var/run/docker.sock]\n",
      "services:\n  relay:\n    image: nginx\n    ports: ['8080:80']\n"
    ]) {
      const response = await app.inject({ method: "POST", url: `/api/v1/workloads/${workload.id}/versions`, payload: { version: "1.0.0", composeYaml, manifest } });
      expect(response.statusCode).toBe(422);
    }
  });

  it("materializes digest-pinned no-secret workloads into the typed agent payload", async () => {
    const { app, store } = await setup();
    const workload = (await app.inject({ method: "POST", url: "/api/v1/workloads", payload: { name: "relay" } })).json();
    const image = `nginx@sha256:${"a".repeat(64)}`;
    const versionResponse = await app.inject({ method: "POST", url: `/api/v1/workloads/${workload.id}/versions`, payload: {
      version: "1.0.0", composeYaml: `services:\n  web:\n    image: ${image}\n    ports: ['8080:80']\n`,
      manifest: { schemaVersion: 1, inputsSchema: {}, secretFiles: [], endpoints: [{ name: "web", protocol: "tcp", port: 8080, scope: "public" }], placement: { requiredRoles: ["redirector"] }, probes: [] }
    } });
    expect(versionResponse.statusCode).toBe(201);
    const credentials = new (await import("../src/services/credential-service.js")).CredentialService(store, config.encryptionKey);
    const workloadService = new (await import("../src/services/workload-service.js")).WorkloadService(store, credentials);
    const environmentSpec = spec(); environmentSpec.deployments = [{ key: "web", nodeKey: "relay", workloadVersionId: versionResponse.json().id, desiredState: "running", dependsOn: [], inputs: {}, exposures: [{ protocol: "tcp", port: 8080, allowedCidrs: ["203.0.113.0/24"] }] }];
    const plan = await workloadService.plan(environmentSpec); expect(plan.blockers).toEqual([]);
    const materialized = await workloadService.materialize(environmentSpec, "11111111-1111-4111-8111-111111111111", 1, plan.resolutions);
    expect(materialized[0]?.payload).toMatchObject({ environmentId: "11111111-1111-4111-8111-111111111111", generation: 1, resolvedImages: { web: `docker.io/library/${image}` }, secretFiles: [], timeoutSeconds: 600 });
  });

  it("materializes stopped workloads as idempotent removal tasks", async () => {
    const { app, store } = await setup();
    const workload = (await app.inject({ method: "POST", url: "/api/v1/workloads", payload: { name: "paused relay" } })).json();
    const image = `nginx@sha256:${"c".repeat(64)}`;
    const version = (await app.inject({ method: "POST", url: `/api/v1/workloads/${workload.id}/versions`, payload: {
      version: "1.0.0", composeYaml: `services:\n  relay:\n    image: ${image}\n`,
      manifest: { schemaVersion: 1, inputsSchema: {}, secretFiles: [], endpoints: [], placement: { requiredRoles: [] }, probes: [] }
    } })).json();
    const credentials = new (await import("../src/services/credential-service.js")).CredentialService(store, config.encryptionKey);
    const service = new (await import("../src/services/workload-service.js")).WorkloadService(store, credentials);
    const environmentSpec = spec(); environmentSpec.deployments = [{ key: "paused", nodeKey: "relay", workloadVersionId: version.id, desiredState: "stopped", dependsOn: [], inputs: {}, exposures: [] }];
    const plan = await service.plan(environmentSpec); const materialized = await service.materialize(environmentSpec, "11111111-1111-4111-8111-111111111111", 2, plan.resolutions);
    expect(materialized[0]).toMatchObject({ desiredState: "stopped", payload: { removeOwnedVolumes: false } });
    expect(materialized[0]?.payload).not.toHaveProperty("composeYaml");
  });

  it("resolves tags once, pins the reviewed digest, and hydrates relative secrets only at dispatch", async () => {
    const store = new MemoryStore(); const Credential = (await import("../src/services/credential-service.js")).CredentialService;
    const Registry = (await import("../src/services/registry-service.js")).RegistryService;
    const Workloads = (await import("../src/services/workload-service.js")).WorkloadService;
    const credentials = new Credential(store, config.encryptionKey);
    const registryCredential = await credentials.create({ name: "Private registry", kind: "registry", registry: "registry.example", username: "robot", secret: "registry-password" });
    const workloadSecret = await credentials.create({ name: "Application token", kind: "opaque", secret: "workload-secret" });
    let requestedAuthorization = "";
    const registry = new Registry(credentials, async (_input, init) => {
      requestedAuthorization = new Headers(init?.headers).get("authorization") ?? "";
      return new Response('{"schemaVersion":2}', { status: 200, headers: { "docker-content-digest": `sha256:${"b".repeat(64)}` } });
    });
    const service = new Workloads(store, credentials, registry);
    const workload = await service.create("Private API");
    const version = await service.createVersion(workload.id, "1.0.0", "services:\n  api:\n    image: registry.example/acme/api:stable\n", {
      schemaVersion: 1, inputsSchema: {}, secretFiles: [{ input: "token", target: "api/token" }], endpoints: [], placement: { requiredRoles: [] }, probes: [{ kind: "container", target: "api", timeoutSeconds: 10 }],
      registryCredentials: [{ registry: "registry.example", credentialId: registryCredential.id }]
    });
    const environmentSpec = spec(); environmentSpec.deployments = [{ key: "api", nodeKey: "relay", workloadVersionId: version.id, desiredState: "running", dependsOn: [], inputs: { token: { kind: "secretRef", credentialId: workloadSecret.id } }, exposures: [] }];
    const plan = await service.plan(environmentSpec);
    expect(plan.blockers).toEqual([]); expect(plan.resolutions[0]?.resolvedImages.api).toBe(`registry.example/acme/api@sha256:${"b".repeat(64)}`);
    expect(requestedAuthorization).toBe(`Basic ${Buffer.from("robot:registry-password").toString("base64")}`);
    const materialized = await service.materialize(environmentSpec, "11111111-1111-4111-8111-111111111111", 3, plan.resolutions);
    expect(JSON.stringify(materialized)).not.toContain("workload-secret");
    expect(materialized[0]?.payload).toMatchObject({ generation: 3, secretFiles: [], probes: [{ kind: "container", target: "api", timeoutSeconds: 10 }] });
    const hydrated = await service.hydrateTaskPayload(materialized[0]!.payload);
    expect(hydrated.secretFiles).toEqual([{ target: expect.stringMatching(/\/3\/secrets\/api\/token$/), contentBase64: Buffer.from("workload-secret").toString("base64") }]);
    expect(hydrated).not.toHaveProperty("secretBindings");
  });
});
