import { randomBytes, randomUUID } from "node:crypto";
import type { Operation, OperationKind, PlanArtifact } from "@infractory/contracts";
import type { ControlPlaneStore } from "../db/store.js";
import { conflict, invalid, notFound } from "../domain/errors.js";
import type { AgentCommandRecord, EnvironmentRecord, OperationRecord, StepDefinition } from "../domain/models.js";
import { digest, validateSpec } from "../domain/spec.js";
import type { InfrastructureAdapter } from "../adapters/infrastructure.js";
import type { AppConfig } from "../config.js";
import type { OperationScheduler } from "./scheduler.js";
import { WorkloadService } from "./workload-service.js";
import { NetworkService } from "./network-service.js";

const TERMINAL = new Set(["succeeded", "blocked", "failed", "needs_reconciliation", "cancelled"]);
const STEPS: Record<OperationKind, StepDefinition[]> = {
  plan: [
    { key: "validate_spec", title: "Validate environment" },
    { key: "observe_provider", title: "Observe current infrastructure" },
    { key: "preview_changes", title: "Generate change plan" }
  ],
  apply: [
    { key: "verify_plan", title: "Verify reviewed plan" },
    { key: "apply_infrastructure", title: "Converge AWS infrastructure" },
    { key: "await_nodes", title: "Wait for nodes" },
    { key: "configure_network", title: "Configure private network" },
    { key: "deploy_workloads", title: "Deploy workloads" },
    { key: "verify_health", title: "Verify environment health" }
  ],
  reconcile: [
    { key: "observe_state", title: "Observe all authorities" },
    { key: "build_repair_plan", title: "Build reviewed repair plan" }
  ],
  destroy: [
    { key: "verify_destroy", title: "Verify destroy request" },
    { key: "remove_workloads", title: "Remove workloads" },
    { key: "detach_adopted", title: "Detach adopted hosts" },
    { key: "destroy_cloud", title: "Destroy managed infrastructure" },
    { key: "audit_residuals", title: "Audit residual resources" }
  ],
  abandon: [
    { key: "audit_residuals", title: "Record residual resources" },
    { key: "record_abandonment", title: "Abandon control" }
  ]
};

type StepOutcome = { kind: "done"; result?: Record<string, unknown> } | { kind: "wait"; message: string } | { kind: "blocked"; code: string; message: string };

export class OperationService {
  constructor(
    private readonly store: ControlPlaneStore,
    private readonly infrastructure: InfrastructureAdapter,
    private readonly scheduler: OperationScheduler,
    private readonly config: AppConfig,
    private readonly workloadService: WorkloadService
  ) {}
  private get workloads(): WorkloadService { return this.workloadService; }
  private get network(): NetworkService { return new NetworkService(this.store, this.config); }

  async create(environmentId: string, kind: OperationKind, revision: number, idempotencyKey: string, options: { retryOfOperationId?: string; planOperationId?: string } = {}): Promise<OperationRecord> {
    if (kind !== "plan" && kind !== "reconcile") {
      const active = await this.store.findActiveOperation(environmentId);
      if (active && active.idempotencyKey !== idempotencyKey) throw conflict("operation_in_progress", "Another environment operation is active", { operationId: active.id });
    }
    const created = await this.store.createOperation({ environmentId, kind, revision, idempotencyKey, steps: STEPS[kind], ...options });
    if (created.created && !this.scheduler.initialEnqueueIsTransactional) await this.scheduler.enqueue(created.operation.id);
    return created.operation;
  }

  async createPlan(environmentId: string, idempotencyKey: string): Promise<OperationRecord> {
    const env = await this.requireEnvironment(environmentId);
    if (["destroying", "destroyed", "abandoned"].includes(env.lifecycle)) throw conflict("invalid_lifecycle", `Cannot plan an environment that is ${env.lifecycle}`);
    return this.create(environmentId, "plan", env.desiredRevision, idempotencyKey);
  }
  async createApply(environmentId: string, planOperationId: string, idempotencyKey: string): Promise<OperationRecord> {
    const env = await this.requireEnvironment(environmentId);
    const plan = await this.requireValidPlan(env, planOperationId);
    if ((plan.plan?.blockers.length ?? 0) > 0) throw conflict("plan_blocked", "The reviewed plan contains blockers");
    return this.create(environmentId, "apply", env.desiredRevision, idempotencyKey, { planOperationId });
  }
  async createReconcile(environmentId: string, idempotencyKey: string): Promise<OperationRecord> {
    const env = await this.requireEnvironment(environmentId); return this.create(environmentId, "reconcile", env.desiredRevision, idempotencyKey);
  }
  async createDestroy(environmentId: string, confirmName: string, acknowledgeResidualRisk: boolean, idempotencyKey: string): Promise<OperationRecord> {
    const env = await this.requireEnvironment(environmentId);
    if (confirmName !== env.name) throw invalid("confirmation_mismatch", "Environment name confirmation does not match");
    if (!acknowledgeResidualRisk) throw invalid("residual_risk_not_acknowledged", "Residual resource risk must be acknowledged");
    if (["destroyed", "abandoned"].includes(env.lifecycle)) throw conflict("invalid_lifecycle", `Environment is already ${env.lifecycle}`);
    return this.create(environmentId, "destroy", env.desiredRevision, idempotencyKey);
  }
  async createAbandon(environmentId: string, confirmName: string, idempotencyKey: string): Promise<OperationRecord> {
    const env = await this.requireEnvironment(environmentId);
    if (confirmName !== env.name) throw invalid("confirmation_mismatch", "Environment name confirmation does not match");
    return this.create(environmentId, "abandon", env.desiredRevision, idempotencyKey);
  }
  async retry(operationId: string, idempotencyKey: string): Promise<OperationRecord> {
    const prior = await this.store.getOperation(operationId); if (!prior) throw notFound("Operation");
    if (!["failed", "blocked", "needs_reconciliation", "cancelled"].includes(prior.state)) throw conflict("operation_not_retryable", `Operation in state '${prior.state}' cannot be retried`);
    return this.create(prior.environmentId, prior.kind, prior.revision, idempotencyKey, {
      retryOfOperationId: prior.id, ...(prior.planOperationId ? { planOperationId: prior.planOperationId } : {})
    });
  }
  async cancel(operationId: string): Promise<OperationRecord> {
    const operation = await this.store.getOperation(operationId); if (!operation) throw notFound("Operation");
    if (TERMINAL.has(operation.state)) throw conflict("operation_terminal", `Operation is already ${operation.state}`);
    await this.store.patchOperation(operation.id, { state: "cancelling" }); await this.store.appendOperationEvent(operation.id, { level: "warning", code: "operation.cancelling", message: "Cancellation requested; the operation will stop at the next safe boundary" });
    await this.scheduler.enqueue(operation.id); return (await this.store.getOperation(operation.id))!;
  }

  async advance(operationId: string): Promise<void> {
    let operation = await this.store.getOperation(operationId); if (!operation || TERMINAL.has(operation.state)) return;
    if (operation.state === "cancelling") {
      const now = new Date().toISOString();
      for (const step of operation.steps.filter(({ state }) => state === "pending" || state === "waiting")) await this.store.patchStep(operation.id, step.id, { state: "cancelled", finishedAt: now });
      await this.store.patchOperation(operation.id, { state: "cancelled", finishedAt: now });
      await this.store.appendOperationEvent(operation.id, { level: "warning", code: "operation.cancelled", message: "Operation cancelled at a safe boundary" }); return;
    }
    const step = operation.steps.find(({ state }) => state !== "succeeded" && state !== "skipped");
    if (!step) { await this.finish(operation); return; }
    if (step.state === "running" && (step.key === "apply_infrastructure" || step.key === "destroy_cloud")) {
      const now = new Date().toISOString();
      await this.store.patchStep(operation.id, step.id, { state: "failed", finishedAt: now, errorCode: "outcome_unknown", errorMessage: "Worker stopped while an external mutation was in progress" });
      await this.store.patchOperation(operation.id, { state: "needs_reconciliation", finishedAt: now });
      await this.markEnvironmentFailure(operation);
      await this.store.appendOperationEvent(operation.id, { level: "error", code: "outcome_unknown", message: "The worker stopped during a provider mutation. Observe and reconcile provider state before retrying; the mutation was not repeated.", stepKey: step.key });
      return;
    }
    if (step.state === "running") await this.store.appendOperationEvent(operation.id, { level: "warning", code: "step.resuming", message: `${step.title} was interrupted before a persisted outcome and will be retried idempotently`, stepKey: step.key });
    const now = new Date().toISOString();
    await this.store.patchOperation(operation.id, { state: "running", startedAt: operation.startedAt ?? now });
    await this.store.patchStep(operation.id, step.id, { state: "running", attempt: step.attempt + 1, startedAt: step.startedAt ?? now, errorCode: null, errorMessage: null });
    await this.store.appendOperationEvent(operation.id, { level: "info", code: "step.started", message: step.title, stepKey: step.key });
    operation = (await this.store.getOperation(operation.id))!;
    try {
      const outcome = await this.executeStep(operation, step.key);
      if (outcome.kind === "wait") {
        await this.store.patchStep(operation.id, step.id, { state: "waiting" });
        await this.store.patchOperation(operation.id, { state: "waiting" });
        await this.store.appendOperationEvent(operation.id, { level: "info", code: "step.waiting", message: outcome.message, stepKey: step.key });
        await this.scheduler.enqueue(operation.id, new Date(Date.now() + 5_000)); return;
      }
      if (outcome.kind === "blocked") {
        await this.store.patchStep(operation.id, step.id, { state: "failed", finishedAt: new Date().toISOString(), errorCode: outcome.code, errorMessage: outcome.message });
        await this.store.patchOperation(operation.id, { state: "blocked", finishedAt: new Date().toISOString() });
        await this.store.appendOperationEvent(operation.id, { level: "warning", code: outcome.code, message: outcome.message, stepKey: step.key }); return;
      }
      const result = { ...(operation.result ?? {}), ...(outcome.result ?? {}) };
      await this.store.patchOperation(operation.id, { result });
      await this.store.patchStep(operation.id, step.id, { state: "succeeded", finishedAt: new Date().toISOString() });
      await this.store.appendOperationEvent(operation.id, { level: "info", code: "step.succeeded", message: `${step.title} completed`, stepKey: step.key });
      const updated = await this.store.getOperation(operation.id);
      if (updated?.steps.every(({ state }) => state === "succeeded" || state === "skipped")) await this.finish(updated); else await this.scheduler.enqueue(operation.id);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown operation failure";
      await this.store.patchStep(operation.id, step.id, { state: "failed", finishedAt: new Date().toISOString(), errorCode: "step_failed", errorMessage: message });
      const ambiguous = step.key === "apply_infrastructure" || step.key === "destroy_cloud";
      await this.store.patchOperation(operation.id, { state: ambiguous ? "needs_reconciliation" : "failed", finishedAt: new Date().toISOString() });
      await this.markEnvironmentFailure(operation);
      await this.store.appendOperationEvent(operation.id, { level: "error", code: ambiguous ? "outcome_unknown" : "step.failed", message: ambiguous ? `${message}. Provider state must be reconciled before retry.` : message, stepKey: step.key });
    }
  }

  private async executeStep(operation: OperationRecord, stepKey: string): Promise<StepOutcome> {
    const env = await this.requireEnvironment(operation.environmentId);
    const revision = await this.store.getRevision(env.id, operation.revision); if (!revision) throw new Error("Requested environment revision no longer exists");
    const spec = revision.spec;
    if (operation.kind === "plan") {
      if (stepKey === "validate_spec") { validateSpec(spec); return { kind: "done" }; }
      const observation = await this.infrastructure.observe(env.id, spec);
      if (stepKey === "observe_provider") return { kind: "done", result: { providerObservation: observation } };
      const changes = await this.infrastructure.preview(env.id, spec, observation);
      const workloadPlan = await this.workloads.plan(spec);
      const createdAt = new Date();
      const plan: PlanArtifact = { revision: revision.revision, revisionDigest: revision.digest, accountId: observation.accountId, region: observation.region, providerObservationDigest: observation.digest, pulumiProgramVersion: this.infrastructure.programVersion, pulumiProviderVersion: this.infrastructure.providerVersion, createdAt: createdAt.toISOString(), expiresAt: new Date(createdAt.getTime() + 15 * 60_000).toISOString(), changes, blockers: workloadPlan.blockers, workloadResolutions: workloadPlan.resolutions };
      await this.store.patchOperation(operation.id, { plan, result: { plan } }); return { kind: "done", result: { plan } };
    }
    if (operation.kind === "apply") {
      if (stepKey === "verify_plan") { await this.requireValidPlan(env, operation.planOperationId ?? ""); await this.store.patchEnvironment(env.id, { lifecycle: "applying", updatedAt: new Date().toISOString() }); return { kind: "done" }; }
      if (stepKey === "apply_infrastructure") {
        const agentBootstrap: Record<string, { enrollmentToken: string; publicUrl: string }> = {};
        for (const node of await this.store.listNodes(env.id)) if (node.origin === "aws") {
          const enrollment = await this.mintEnrollment(node.id);
          agentBootstrap[node.nodeKey] = { enrollmentToken: enrollment.token, publicUrl: this.config.publicUrl };
        }
        const applied = await this.infrastructure.apply({ environmentId: env.id, revision: operation.revision, spec, agentBootstrap });
        if (this.config.infrastructureMode === "fake") for (const node of await this.store.listNodes(env.id)) await this.store.patchNode(node.id, { lifecycle: "active", health: "online", lastSeenAt: new Date().toISOString() });
        return { kind: "done", result: { infrastructure: applied } };
      }
      if (stepKey === "await_nodes") {
        const nodes = await this.store.listNodes(env.id); const pending = nodes.filter((node) => node.lifecycle !== "active");
        return pending.length ? { kind: "wait", message: `Waiting for ${pending.length} node${pending.length === 1 ? "" : "s"} to enroll` } : { kind: "done" };
      }
      if (stepKey === "configure_network") {
        if (this.config.infrastructureMode === "fake") return { kind: "done" };
        const authority = await this.network.ensureAuthority(env.id, spec); const nodes = await this.store.listNodes(env.id);
        const lighthouseNodes = nodes.filter((node) => spec.network.lighthouseNodeKeys.includes(node.nodeKey));
        const lighthouseResult = await this.ensureTasks(operation, "EnsureNebula", lighthouseNodes, (node) => ({ environmentId: env.id, cidr: spec.network.cidr, lighthouse: true, groups: spec.nodes.find(({ key }) => key === node.nodeKey)?.roles ?? [], caCertificate: authority.caCertificate, config: this.network.renderConfig(env.id, spec, node.nodeKey, {}) }));
        if (lighthouseResult.kind !== "done") return lighthouseResult;
        const memberships = await this.store.listNetworkMemberships(env.id); const outputs = (operation.result?.["infrastructure"] as { outputs?: { publicEndpoints?: Record<string, string> } } | undefined)?.outputs;
        const endpoints: Record<string, string> = {};
        for (const lighthouseNode of lighthouseNodes) {
          const membership = memberships.find(({ nodeId }) => nodeId === lighthouseNode.id); const endpoint = outputs?.publicEndpoints?.[lighthouseNode.nodeKey];
          if (!membership || !endpoint) return { kind: "blocked", code: "lighthouse_endpoint_unavailable", message: `No validated public endpoint is available for lighthouse '${lighthouseNode.name}'` };
          endpoints[membership.overlayAddress.split("/")[0]!] = endpoint;
        }
        return this.ensureTasks(operation, "EnsureNebula", nodes.filter((node) => !spec.network.lighthouseNodeKeys.includes(node.nodeKey)), (node) => ({ environmentId: env.id, cidr: spec.network.cidr, lighthouse: false, groups: spec.nodes.find(({ key }) => key === node.nodeKey)?.roles ?? [], caCertificate: authority.caCertificate, config: this.network.renderConfig(env.id, spec, node.nodeKey, endpoints) }));
      }
      if (stepKey === "deploy_workloads") {
        // The provider observation is validated once at verify_plan, before any
        // external mutation. By this point apply_infrastructure has intentionally
        // changed provider state, so re-running the pre-apply drift check would
        // reject the very changes this operation just made. Continue with the
        // same immutable reviewed artifact instead.
        const reviewedPlan = await this.store.getLatestSuccessfulPlan(env.id, operation.planOperationId ?? "");
        if (!reviewedPlan?.plan) throw invalid("invalid_plan", "The apply operation lost its reviewed plan artifact");
        const nodes = await this.store.listNodes(env.id); const materialized = await this.workloads.materialize(spec, env.id, operation.revision, reviewedPlan.plan!.workloadResolutions);
        return this.ensureTaskTargets(operation, "ApplyWorkload", materialized.map((item) => ({ node: nodes.find(({ nodeKey }) => nodeKey === item.nodeKey)!, payload: item.payload })));
      }
      const nodes = await this.store.listNodes(env.id);
      if (nodes.some((node) => node.health !== "online")) return { kind: "blocked", code: "nodes_unhealthy", message: "One or more nodes are not reporting healthy observations" };
      return { kind: "done" };
    }
    if (operation.kind === "reconcile") {
      const observation = await this.infrastructure.observe(env.id, spec);
      if (stepKey === "observe_state") return { kind: "done", result: { providerObservation: observation } };
      const changes = await this.infrastructure.preview(env.id, spec, observation); const now = new Date(); const workloadPlan = await this.workloads.plan(spec);
      const plan: PlanArtifact = { revision: revision.revision, revisionDigest: revision.digest, accountId: observation.accountId, region: observation.region, providerObservationDigest: observation.digest, pulumiProgramVersion: this.infrastructure.programVersion, pulumiProviderVersion: this.infrastructure.providerVersion, createdAt: now.toISOString(), expiresAt: new Date(now.getTime() + 15 * 60_000).toISOString(), changes, blockers: workloadPlan.blockers, workloadResolutions: workloadPlan.resolutions };
      await this.store.patchOperation(operation.id, { plan, result: { reconciliationPlan: plan } }); return { kind: "done", result: { reconciliationPlan: plan } };
    }
    if (operation.kind === "destroy") {
      if (stepKey === "verify_destroy") { await this.store.patchEnvironment(env.id, { lifecycle: "destroying", updatedAt: new Date().toISOString() }); return { kind: "done" }; }
      const nodes = await this.store.listNodes(env.id);
      if (stepKey === "remove_workloads") return this.ensureTasks(operation, "CleanupNode", nodes.filter((node) => node.health === "online"), () => ({ environmentId: env.id }));
      if (stepKey === "detach_adopted") {
        const offline = nodes.filter((node) => node.origin === "adopted" && node.health !== "online" && node.lifecycle !== "detached");
        if (offline.length) return { kind: "blocked", code: "adopted_host_offline", message: `Cleanup is incomplete on adopted hosts: ${offline.map(({ name }) => name).join(", ")}. Force-detach or reconnect them before retrying.` };
        for (const node of nodes.filter(({ origin }) => origin === "adopted")) await this.store.patchNode(node.id, { lifecycle: "detached", health: "unknown" }); return { kind: "done" };
      }
      if (stepKey === "destroy_cloud") return { kind: "done", result: { destroy: await this.infrastructure.destroy(env.id, spec) } };
      const residuals = await this.infrastructure.auditResiduals(env.id, spec);
      if (residuals.length) return { kind: "blocked", code: "residual_resources", message: `${residuals.length} managed resource${residuals.length === 1 ? " remains" : "s remain"}; broad deletion was not attempted` };
      return { kind: "done", result: { residualResources: [] } };
    }
    const residuals = await this.infrastructure.auditResiduals(env.id, spec);
    if (stepKey === "audit_residuals") return { kind: "done", result: { residualResources: residuals } };
    await this.store.patchEnvironment(env.id, { lifecycle: "abandoned", health: "unknown", updatedAt: new Date().toISOString() });
    return { kind: "done", result: { abandoned: true, residualResources: residuals } };
  }

  private async ensureTasks(operation: OperationRecord, kind: AgentCommandRecord["kind"], nodes: Awaited<ReturnType<ControlPlaneStore["listNodes"]>>, payload: (node: Awaited<ReturnType<ControlPlaneStore["listNodes"]>>[number]) => Record<string, unknown>): Promise<StepOutcome> {
    return this.ensureTaskTargets(operation, kind, nodes.map((node) => ({ node, payload: payload(node) })));
  }
  private async ensureTaskTargets(operation: OperationRecord, kind: AgentCommandRecord["kind"], targets: Array<{ node: Awaited<ReturnType<ControlPlaneStore["listNodes"]>>[number]; payload: Record<string, unknown> }>): Promise<StepOutcome> {
    if (this.config.infrastructureMode === "fake") return { kind: "done" };
    const prefix = `${operation.id}:${kind}:`;
    for (const { node, payload } of targets) await this.store.createAgentCommand({ nodeId: node.id, actionKey: `${prefix}${node.generation}`, nodeGeneration: node.generation, kind, payload, deadline: new Date(Date.now() + 30 * 60_000).toISOString() });
    await this.store.expireAgentCommands(targets.map(({ node }) => node.id), prefix, new Date().toISOString());
    const commands = await this.store.listAgentCommands(targets.map(({ node }) => node.id), prefix);
    const failed = commands.find(({ state }) => state === "failed" || state === "stale");
    if (failed) return { kind: "blocked", code: failed.errorCode ?? "agent_task_failed", message: failed.errorMessage ?? `${kind} failed on a node` };
    return commands.length === targets.length && commands.every(({ state }) => state === "succeeded") ? { kind: "done" } : { kind: "wait", message: `Waiting for ${kind} on ${targets.length} node${targets.length === 1 ? "" : "s"}` };
  }

  private async mintEnrollment(nodeId: string): Promise<{ token: string; expiresAt: string }> {
    const token = randomBytes(32).toString("base64url"); const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString();
    await this.store.createEnrollment({ id: randomUUID(), nodeId, tokenHash: digest(`${this.config.tokenPepper}:${token}`), expiresAt, consumedAt: null, createdAt: new Date().toISOString() });
    await this.store.patchNode(nodeId, { lifecycle: "enrolling" }); return { token, expiresAt };
  }
  async createEnrollment(environmentId: string, nodeId: string): Promise<{ token: string; expiresAt: string }> {
    const node = await this.store.getNode(nodeId); if (!node) throw notFound("Node");
    if (node.environmentId !== environmentId) throw notFound("Node");
    if (node.origin !== "adopted") throw conflict("managed_node_enrollment", "Managed node enrollment is created by apply");
    return this.mintEnrollment(nodeId);
  }
  async forceDetach(environmentId: string, nodeId: string): Promise<void> {
    const node = await this.store.getNode(nodeId); if (!node || node.environmentId !== environmentId) throw notFound("Node");
    if (node.origin !== "adopted") throw invalid("managed_node_detach", "Managed AWS nodes cannot be force-detached");
    await this.store.revokeNodeIdentities(nodeId);
    await this.store.patchNode(nodeId, { lifecycle: "detached", health: "unknown" });
  }

  private async requireEnvironment(id: string): Promise<EnvironmentRecord> { const env = await this.store.getEnvironment(id); if (!env) throw notFound("Environment"); return env; }
  private async requireValidPlan(env: EnvironmentRecord, operationId: string): Promise<OperationRecord> {
    const planOperation = await this.store.getLatestSuccessfulPlan(env.id, operationId); if (!planOperation?.plan) throw invalid("invalid_plan", "A successful plan operation is required");
    const revision = await this.store.getRevision(env.id, env.desiredRevision); if (!revision) throw new Error("Desired revision is missing");
    if (planOperation.plan.revision !== env.desiredRevision || planOperation.plan.revisionDigest !== revision.digest) throw conflict("stale_plan", "The environment changed after this plan was generated");
    if (new Date(planOperation.plan.expiresAt).getTime() <= Date.now()) throw conflict("expired_plan", "The reviewed plan has expired");
    if (planOperation.plan.pulumiProgramVersion !== this.infrastructure.programVersion || planOperation.plan.pulumiProviderVersion !== this.infrastructure.providerVersion) throw conflict("stale_plan", "Provider implementation changed after this plan was generated");
    const observation = await this.infrastructure.observe(env.id, revision.spec);
    if (observation.accountId !== planOperation.plan.accountId || observation.region !== planOperation.plan.region) throw conflict("provider_identity_changed", "AWS account or region changed after planning; generate a new plan");
    if (observation.digest !== planOperation.plan.providerObservationDigest) throw conflict("provider_drift", "Provider state changed after planning; generate a new plan");
    return planOperation;
  }
  private async finish(operation: OperationRecord): Promise<void> {
    const now = new Date().toISOString(); await this.store.patchOperation(operation.id, { state: "succeeded", finishedAt: now });
    if (operation.kind === "apply") await this.store.patchEnvironment(operation.environmentId, { lifecycle: "active", health: "healthy", appliedRevision: operation.revision, updatedAt: now });
    if (operation.kind === "destroy") await this.store.patchEnvironment(operation.environmentId, { lifecycle: "destroyed", health: "unknown", updatedAt: now });
    await this.store.appendOperationEvent(operation.id, { level: "info", code: "operation.succeeded", message: `${operation.kind} operation completed` });
  }
  private async markEnvironmentFailure(operation: OperationRecord): Promise<void> {
    if (operation.kind === "apply") await this.store.patchEnvironment(operation.environmentId, { lifecycle: "apply_failed", health: "degraded", updatedAt: new Date().toISOString() });
    if (operation.kind === "destroy") await this.store.patchEnvironment(operation.environmentId, { lifecycle: "destroy_failed", health: "degraded", updatedAt: new Date().toISOString() });
  }
}
