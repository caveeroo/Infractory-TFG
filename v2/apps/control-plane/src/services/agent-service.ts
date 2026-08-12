import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { AgentTask, CompleteTaskRequest, EnrollAgentRequest, HeartbeatRequest, TaskEventRequest } from "@infractory/contracts";
import type { ControlPlaneStore } from "../db/store.js";
import { conflict, notFound, unauthorized } from "../domain/errors.js";
import { digest } from "../domain/spec.js";
import type { AppConfig } from "../config.js";
import type { WorkloadService } from "./workload-service.js";

export class AgentService {
  constructor(private readonly store: ControlPlaneStore, private readonly config: AppConfig, private readonly workloads: WorkloadService) {}
  private sanitize(message: string): string {
    return message
      .replace(/(bearer\s+)[A-Za-z0-9._~-]+/gi, "$1[REDACTED]")
      .replace(/-----BEGIN [^-]+ PRIVATE KEY-----[\s\S]*?-----END [^-]+ PRIVATE KEY-----/g, "[REDACTED PRIVATE KEY]")
      .replace(/((?:token|secret|password)[=:]\s*)[^\s,;]+/gi, "$1[REDACTED]");
  }
  private hash(token: string): string { return digest(`${this.config.tokenPepper}:${token}`); }
  private constantEqual(a: string, b: string): boolean { const left = Buffer.from(a); const right = Buffer.from(b); return left.length === right.length && timingSafeEqual(left, right); }

  async enroll(input: EnrollAgentRequest): Promise<{ nodeId: string; deviceToken: string; expiresAt: string; heartbeatIntervalSeconds: number }> {
    const deviceToken = randomBytes(32).toString("base64url"); const now = new Date(); const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60_000).toISOString();
    const enrollment = await this.store.consumeEnrollment(this.hash(input.token), { id: randomUUID(), nodeId: "00000000-0000-0000-0000-000000000000", tokenHash: this.hash(deviceToken), expiresAt, revokedAt: null, createdAt: now.toISOString() });
    if (!enrollment) throw unauthorized();
    const node = await this.store.getNode(enrollment.nodeId); if (!node) throw notFound("Enrollment node");
    await this.store.patchNode(node.id, { lifecycle: "active", health: "online", lastSeenAt: now.toISOString() });
    await this.store.saveObservation(node.id, { nodeId: node.id, generation: node.generation, agentVersion: "enrolling", capabilities: input.capabilities, observation: { publicKey: input.publicKey }, observedAt: now.toISOString() });
    return { nodeId: node.id, deviceToken, expiresAt, heartbeatIntervalSeconds: 15 };
  }

  async authenticate(header: string | undefined): Promise<{ nodeId: string; tokenHash: string }> {
    const match = /^Bearer ([A-Za-z0-9_-]{32,})$/.exec(header ?? ""); if (!match?.[1]) throw unauthorized();
    const hash = this.hash(match[1]); const identity = await this.store.findIdentityByToken(hash); if (!identity || !this.constantEqual(identity.tokenHash, hash)) throw unauthorized();
    const node = await this.store.getNode(identity.nodeId);
    if (!node || node.lifecycle === "detached" || node.lifecycle === "removed") throw unauthorized();
    return { nodeId: identity.nodeId, tokenHash: hash };
  }
  async rotate(nodeId: string, currentTokenHash: string): Promise<{ deviceToken: string; expiresAt: string; oldTokenValidUntil: string }> {
    const deviceToken = randomBytes(32).toString("base64url"); const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60_000).toISOString(); const oldTokenValidUntil = new Date(now.getTime() + 5 * 60_000).toISOString();
    await this.store.rotateIdentity(currentTokenHash, { id: randomUUID(), nodeId, tokenHash: this.hash(deviceToken), expiresAt, revokedAt: null, createdAt: now.toISOString() }, oldTokenValidUntil);
    return { deviceToken, expiresAt, oldTokenValidUntil };
  }

  async heartbeat(nodeId: string, input: HeartbeatRequest): Promise<void> {
    const node = await this.store.getNode(nodeId); if (!node) throw unauthorized();
    if (input.generation !== node.generation) throw conflict("stale_node_generation", `Agent generation ${input.generation} does not match desired generation ${node.generation}`);
    const observedAt = new Date().toISOString();
    await this.store.saveObservation(nodeId, { nodeId, generation: input.generation, agentVersion: input.agentVersion, capabilities: input.capabilities, observation: input.observation, observedAt });
    if (!input.capabilities.ntpSynchronized || input.capabilities.clockOffsetSeconds === null || Math.abs(input.capabilities.clockOffsetSeconds) > 5) await this.store.patchNode(nodeId, { health: "degraded" });
  }

  async nextTask(nodeId: string, waitSeconds: number): Promise<AgentTask | null> {
    const deadline = Date.now() + Math.min(30, Math.max(0, waitSeconds)) * 1000;
    do {
      const observation = await this.store.getObservation(nodeId);
      const allowMutating = observation?.capabilities.ntpSynchronized === true && observation.capabilities.clockOffsetSeconds !== null && Math.abs(observation.capabilities.clockOffsetSeconds) <= 5;
      const leaseToken = randomBytes(32).toString("base64url"); const leaseExpiresAt = new Date(Date.now() + 30 * 60_000).toISOString();
      const command = await this.store.claimAgentCommand(nodeId, new Date().toISOString(), leaseExpiresAt, this.hash(leaseToken), allowMutating);
      if (command) {
        const node = await this.store.getNode(nodeId); if (!node) throw unauthorized();
        if (command.nodeGeneration !== node.generation) {
          await this.store.completeAgentCommand(command.id, nodeId, this.hash(leaseToken), "stale", {}, "stale_node_generation", "Command targets an obsolete node generation");
          continue;
        }
        const payload = command.kind === "ApplyWorkload" ? await this.workloads.hydrateTaskPayload(command.payload) : command.payload;
        return { taskId: command.id, actionKey: command.actionKey, nodeGeneration: command.nodeGeneration, kind: command.kind, payload, attempt: command.attempt, leaseToken, leaseExpiresAt, deadline: command.deadline } as AgentTask;
      }
      if (Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 500));
    } while (Date.now() < deadline);
    return null;
  }

  async event(nodeId: string, commandId: string, input: TaskEventRequest): Promise<void> {
    if (!await this.store.appendAgentCommandEvent(commandId, nodeId, this.hash(input.leaseToken), input.sequence, input.level, this.sanitize(input.message))) throw conflict("invalid_task_lease", "Task lease is invalid, expired, or belongs to another agent");
  }
  async complete(nodeId: string, commandId: string, input: CompleteTaskRequest): Promise<void> {
    if (!await this.store.completeAgentCommand(commandId, nodeId, this.hash(input.leaseToken), input.outcome, input.result, input.errorCode, input.errorMessage)) throw conflict("invalid_task_lease", "Task lease is invalid, expired, or belongs to another agent");
  }
}
