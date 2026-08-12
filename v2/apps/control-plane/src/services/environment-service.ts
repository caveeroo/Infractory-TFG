import { randomUUID } from "node:crypto";
import type { Environment, EnvironmentSpec } from "@infractory/contracts";
import type { ControlPlaneStore } from "../db/store.js";
import type { EnvironmentRecord, NodeRecord, RevisionRecord } from "../domain/models.js";
import { conflict, notFound } from "../domain/errors.js";
import { digest, normalizeSpec, validateSpec } from "../domain/spec.js";

export class EnvironmentService {
  constructor(private readonly store: ControlPlaneStore) {}

  private nodes(environmentId: string, spec: EnvironmentSpec, existing: NodeRecord[] = [], previousSpec?: EnvironmentSpec): NodeRecord[] {
    const networkChanged = previousSpec !== undefined && digest(previousSpec.network) !== digest(spec.network);
    return spec.nodes.map((node) => {
      const current = existing.find((item) => item.nodeKey === node.key);
      const previousNode = previousSpec?.nodes.find((item) => item.key === node.key);
      const desiredConfigurationChanged = current !== undefined && (previousNode === undefined || networkChanged || digest(previousNode) !== digest(node));
      return current ? {
        ...current,
        name: node.name,
        origin: node.source.kind,
        generation: current.generation + (desiredConfigurationChanged ? 1 : 0),
        ...(previousNode === undefined ? { lifecycle: "pending" as const, health: "unknown" as const, lastSeenAt: null } : {})
      } : {
        id: randomUUID(), environmentId, nodeKey: node.key, name: node.name, origin: node.source.kind,
        generation: 0, lifecycle: "pending", health: "unknown", lastSeenAt: null
      };
    });
  }

  async create(specInput: EnvironmentSpec): Promise<Environment> {
    const spec = normalizeSpec(specInput); validateSpec(spec);
    const id = randomUUID(); const now = new Date().toISOString(); const revisionDigest = digest(spec);
    const record: EnvironmentRecord = {
      id, name: spec.name, lifecycle: "draft", health: "unknown", desiredRevision: 1, appliedRevision: null,
      expiresAt: spec.expiresAt ?? null, createdAt: now, updatedAt: now, etag: revisionDigest
    };
    const revision: RevisionRecord = { id: randomUUID(), environmentId: id, revision: 1, digest: revisionDigest, spec, createdAt: now };
    await this.store.createEnvironment(record, revision, this.nodes(id, spec));
    return { ...record, spec };
  }

  async list(limit: number, cursor?: string): Promise<{ items: Environment[]; nextCursor: string | null }> {
    const page = await this.store.listEnvironments(limit, cursor);
    const now = Date.now();
    const items = await Promise.all(page.items.map(async (record) => {
      const nodes = await this.store.listNodes(record.id);
      const stale = nodes.some((node) => node.lastSeenAt && now - new Date(node.lastSeenAt).getTime() > 60_000);
      return { ...record, health: stale ? "unreachable" as const : record.health, spec: (await this.store.getRevision(record.id, record.desiredRevision))!.spec };
    }));
    return { items, nextCursor: page.nextCursor };
  }

  async get(id: string): Promise<Environment> {
    const record = await this.store.getEnvironment(id); if (!record) throw notFound("Environment");
    const revision = await this.store.getRevision(id, record.desiredRevision); if (!revision) throw new Error("Environment revision is missing");
    const nodes = await this.store.listNodes(id); const stale = nodes.some((node) => node.lastSeenAt && Date.now() - new Date(node.lastSeenAt).getTime() > 60_000);
    return { ...record, health: stale ? "unreachable" : record.health, spec: revision.spec };
  }

  async updateSpec(id: string, expectedEtag: string, specInput: EnvironmentSpec): Promise<Environment> {
    const current = await this.get(id);
    if (current.etag !== expectedEtag.replaceAll('"', "")) throw conflict("etag_mismatch", "Environment changed since it was loaded", { currentEtag: current.etag });
    if (current.lifecycle !== "draft" && current.lifecycle !== "active" && current.lifecycle !== "apply_failed") throw conflict("environment_busy", `Cannot change an environment while it is ${current.lifecycle}`);
    if (await this.store.findActiveOperation(id)) throw conflict("operation_in_progress", "Another operation is already changing this environment");
    const spec = normalizeSpec(specInput); validateSpec(spec);
    const currentNodes = await this.store.listNodes(id);
    for (const node of spec.nodes) {
      const prior = currentNodes.find((item) => item.nodeKey === node.key);
      if (prior && prior.origin !== node.source.kind) throw conflict("node_origin_immutable", `Node '${node.key}' cannot change between AWS-managed and adopted; use a new node key`);
    }
    const revisionDigest = digest(spec);
    if (revisionDigest === current.etag) return current;
    const now = new Date().toISOString(); const revisionNumber = current.desiredRevision + 1;
    const record: EnvironmentRecord = { ...current, name: spec.name, health: current.appliedRevision === null ? current.health : "degraded", desiredRevision: revisionNumber, expiresAt: spec.expiresAt ?? null, updatedAt: now, etag: revisionDigest };
    const revision: RevisionRecord = { id: randomUUID(), environmentId: id, revision: revisionNumber, digest: revisionDigest, spec, createdAt: now };
    await this.store.updateEnvironment(record, revision, this.nodes(id, spec, currentNodes, current.spec));
    return { ...record, spec };
  }
  async listNodes(id: string): Promise<NodeRecord[]> {
    await this.get(id); const now = Date.now();
    return (await this.store.listNodes(id)).map((node) => node.lastSeenAt && now - new Date(node.lastSeenAt).getTime() > 60_000 ? { ...node, health: "offline" } : node);
  }

  async clone(id: string, name: string): Promise<Environment> {
    const source = await this.get(id);
    const { expiresAt: _, ...spec } = source.spec;
    return this.create({ ...spec, name });
  }
}
