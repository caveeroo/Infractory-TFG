import { randomUUID } from "node:crypto";
import { sql, type Kysely } from "kysely";
import type { EnvironmentSpec, OperationEvent, OperationStep, PlanArtifact, WorkloadManifest } from "@infractory/contracts";
import type {
  AgentCommandCreate, AgentCommandRecord, ConnectionRecord, CredentialPublicRecord, CredentialRecord, EnrollmentRecord, EnvironmentRecord, EventInput, IdentityRecord,
  NetworkAuthorityRecord, NetworkMembershipRecord, NodeRecord, ObservationRecord, OperationCreate, OperationPatch, OperationRecord, RevisionRecord, StepPatch,
  WorkloadRecord, WorkloadVersionRecord
} from "../domain/models.js";
import type { Database } from "./database.js";
import type { ControlPlaneStore } from "./store.js";

type Json = Record<string, unknown>;
const iso = (value: Date | string | null): string | null => value === null ? null : value instanceof Date ? value.toISOString() : value;
const json = <T>(value: unknown): T => typeof value === "string" ? JSON.parse(value) as T : value as T;

type EnvRow = Omit<EnvironmentRecord, "createdAt" | "updatedAt" | "expiresAt"> & { createdAt: Date | string; updatedAt: Date | string; expiresAt: Date | string | null; spec: EnvironmentSpec };
function mapEnvironment(row: EnvRow): EnvironmentRecord {
  return { ...row, expiresAt: iso(row.expiresAt), createdAt: iso(row.createdAt)!, updatedAt: iso(row.updatedAt)! };
}

type OpRow = Omit<OperationRecord, "steps" | "createdAt" | "startedAt" | "finishedAt"> & { createdAt: Date | string; startedAt: Date | string | null; finishedAt: Date | string | null };
type StepRow = Omit<OperationStep, "startedAt" | "finishedAt"> & { startedAt: Date | string | null; finishedAt: Date | string | null };

export class PostgresStore implements ControlPlaneStore {
  constructor(private readonly db: Kysely<Database>, private readonly enqueueGraphileJobs: boolean) {}

  async createEnvironment(environment: EnvironmentRecord, revision: RevisionRecord, nodes: NodeRecord[]): Promise<void> {
    await this.db.transaction().execute(async (trx) => {
      await sql`insert into environments (id,name,lifecycle,health,desired_revision,applied_revision,expires_at,created_at,updated_at,etag)
        values (${environment.id}::uuid,${environment.name},${environment.lifecycle},${environment.health},${environment.desiredRevision},${environment.appliedRevision},${environment.expiresAt}::timestamptz,${environment.createdAt}::timestamptz,${environment.updatedAt}::timestamptz,${environment.etag})`.execute(trx);
      await sql`insert into environment_revisions (id,environment_id,revision,digest,spec,created_at)
        values (${revision.id}::uuid,${revision.environmentId}::uuid,${revision.revision},${revision.digest},${JSON.stringify(revision.spec)}::jsonb,${revision.createdAt}::timestamptz)`.execute(trx);
      for (const node of nodes) await this.insertNode(trx, node);
    });
  }

  async listEnvironments(limit: number, cursor?: string): Promise<{ items: EnvironmentRecord[]; nextCursor: string | null }> {
    const offset = cursor ? Math.max(0, Number.parseInt(Buffer.from(cursor, "base64url").toString("utf8"), 10)) : 0;
    const result = await sql<EnvRow>`select e.*, r.spec from environments e join environment_revisions r on r.environment_id=e.id and r.revision=e.desired_revision
      order by e.created_at desc,e.id desc limit ${limit + 1} offset ${offset}`.execute(this.db);
    const rows = result.rows.map(mapEnvironment);
    return { items: rows.slice(0, limit), nextCursor: rows.length > limit ? Buffer.from(String(offset + limit)).toString("base64url") : null };
  }

  async getEnvironment(id: string): Promise<EnvironmentRecord | null> {
    const result = await sql<EnvRow>`select e.*, r.spec from environments e join environment_revisions r on r.environment_id=e.id and r.revision=e.desired_revision where e.id=${id}::uuid`.execute(this.db);
    return result.rows[0] ? mapEnvironment(result.rows[0]) : null;
  }

  async getRevision(environmentId: string, revision?: number): Promise<RevisionRecord | null> {
    type Row = Omit<RevisionRecord, "createdAt"> & { createdAt: Date | string };
    const result = revision === undefined
      ? await sql<Row>`select * from environment_revisions where environment_id=${environmentId}::uuid order by revision desc limit 1`.execute(this.db)
      : await sql<Row>`select * from environment_revisions where environment_id=${environmentId}::uuid and revision=${revision}`.execute(this.db);
    const row = result.rows[0];
    return row ? { ...row, spec: json<EnvironmentSpec>(row.spec), createdAt: iso(row.createdAt)! } : null;
  }

  async updateEnvironment(environment: EnvironmentRecord, revision: RevisionRecord, nodes: NodeRecord[]): Promise<void> {
    await this.db.transaction().execute(async (trx) => {
      const updated = await sql`update environments set name=${environment.name},lifecycle=${environment.lifecycle},health=${environment.health},desired_revision=${environment.desiredRevision},applied_revision=${environment.appliedRevision},expires_at=${environment.expiresAt}::timestamptz,updated_at=${environment.updatedAt}::timestamptz,etag=${environment.etag}
        where id=${environment.id}::uuid and desired_revision=${environment.desiredRevision - 1}`.execute(trx);
      if (Number(updated.numAffectedRows) !== 1) throw new Error("Concurrent environment update");
      await sql`insert into environment_revisions (id,environment_id,revision,digest,spec,created_at) values (${revision.id}::uuid,${revision.environmentId}::uuid,${revision.revision},${revision.digest},${JSON.stringify(revision.spec)}::jsonb,${revision.createdAt}::timestamptz)`.execute(trx);
      await sql`update nodes set lifecycle=case when origin='adopted' then 'detached' else 'removed' end,health='unknown'
        where environment_id=${environment.id}::uuid and not (node_key = any(${sql.val(nodes.map(({ nodeKey }) => nodeKey))}::text[]))`.execute(trx);
      await sql`update node_identities set revoked_at=now() where node_id in (select id from nodes where environment_id=${environment.id}::uuid and lifecycle in ('detached','removed')) and revoked_at is null`.execute(trx);
      for (const node of nodes) await sql`insert into nodes (id,environment_id,node_key,name,origin,generation,lifecycle,health,last_seen_at)
        values (${node.id}::uuid,${node.environmentId}::uuid,${node.nodeKey},${node.name},${node.origin},${node.generation},${node.lifecycle},${node.health},${node.lastSeenAt}::timestamptz)
        on conflict (environment_id,node_key) do update set name=excluded.name,origin=excluded.origin,generation=excluded.generation,lifecycle=excluded.lifecycle,health=excluded.health,last_seen_at=excluded.last_seen_at`.execute(trx);
    });
  }
  async patchEnvironment(id: string, patch: Partial<Pick<EnvironmentRecord, "lifecycle" | "health" | "appliedRevision" | "updatedAt">>): Promise<void> {
    await sql`update environments set lifecycle=coalesce(${patch.lifecycle ?? null},lifecycle),health=coalesce(${patch.health ?? null},health),
      applied_revision=case when ${patch.appliedRevision === undefined} then applied_revision else ${patch.appliedRevision ?? null} end,
      updated_at=coalesce(${patch.updatedAt ?? null}::timestamptz,updated_at) where id=${id}::uuid`.execute(this.db);
  }

  private async insertNode(db: Kysely<Database>, node: NodeRecord): Promise<void> {
    await sql`insert into nodes (id,environment_id,node_key,name,origin,generation,lifecycle,health,last_seen_at)
      values (${node.id}::uuid,${node.environmentId}::uuid,${node.nodeKey},${node.name},${node.origin},${node.generation},${node.lifecycle},${node.health},${node.lastSeenAt}::timestamptz)`.execute(db);
  }

  async createOperation(input: OperationCreate): Promise<{ operation: OperationRecord; created: boolean }> {
    return this.db.transaction().execute(async (trx) => {
      const id = randomUUID(); const now = new Date().toISOString();
      const inserted = await sql<{ id: string }>`insert into operations (id,environment_id,kind,state,revision,idempotency_key,retry_of_operation_id,plan_operation_id,created_at)
        values (${id}::uuid,${input.environmentId}::uuid,${input.kind},'queued',${input.revision},${input.idempotencyKey},${input.retryOfOperationId ?? null}::uuid,${input.planOperationId ?? null}::uuid,${now}::timestamptz)
        on conflict (environment_id,idempotency_key) do nothing returning id`.execute(trx);
      const created = inserted.rows.length === 1;
      const operationId = inserted.rows[0]?.id ?? (await sql<{ id: string }>`select id from operations where environment_id=${input.environmentId}::uuid and idempotency_key=${input.idempotencyKey}`.execute(trx)).rows[0]?.id;
      if (!operationId) throw new Error("Could not create or resolve operation");
      if (created) {
        for (const [position, step] of input.steps.entries()) await sql`insert into operation_steps (id,operation_id,key,title,position,state,attempt)
          values (${randomUUID()}::uuid,${operationId}::uuid,${step.key},${step.title},${position},'pending',0)`.execute(trx);
        await sql`insert into operation_events (operation_id,level,code,message,created_at) values (${operationId}::uuid,'info','operation.queued',${`${input.kind} operation queued`},${now}::timestamptz)`.execute(trx);
        if (this.enqueueGraphileJobs) await sql`select graphile_worker.add_job('advance_operation'::text, json_build_object('operationId'::text,${operationId}::text)::json, max_attempts := 3, job_key := ${`operation:${operationId}`}::text)`.execute(trx);
      }
      const operation = await this.getOperationWith(trx, operationId);
      if (!operation) throw new Error("Created operation could not be loaded");
      return { operation, created };
    });
  }

  private async getOperationWith(db: Kysely<Database>, id: string): Promise<OperationRecord | null> {
    const operationResult = await sql<OpRow>`select * from operations where id=${id}::uuid`.execute(db);
    const row = operationResult.rows[0]; if (!row) return null;
    const stepResult = await sql<StepRow>`select * from operation_steps where operation_id=${id}::uuid order by position`.execute(db);
    return {
      ...row, result: row.result === null ? null : json<Json>(row.result), plan: row.plan === null ? null : json<PlanArtifact>(row.plan),
      createdAt: iso(row.createdAt)!, startedAt: iso(row.startedAt), finishedAt: iso(row.finishedAt),
      steps: stepResult.rows.map((step) => ({ ...step, startedAt: iso(step.startedAt), finishedAt: iso(step.finishedAt) }))
    };
  }
  async getOperation(id: string): Promise<OperationRecord | null> { return this.getOperationWith(this.db, id); }
  async findActiveOperation(environmentId: string): Promise<OperationRecord | null> {
    const result = await sql<{ id: string }>`select id from operations where environment_id=${environmentId}::uuid and state in ('queued','running','waiting','cancelling') order by created_at limit 1`.execute(this.db);
    return result.rows[0] ? this.getOperation(result.rows[0].id) : null;
  }
  async patchOperation(id: string, patch: OperationPatch): Promise<void> {
    await sql`update operations set state=coalesce(${patch.state ?? null},state), result=case when ${patch.result === undefined} then result else ${patch.result === undefined ? null : JSON.stringify(patch.result)}::jsonb end,
      plan=case when ${patch.plan === undefined} then plan else ${patch.plan === undefined ? null : JSON.stringify(patch.plan)}::jsonb end,
      started_at=case when ${patch.startedAt === undefined} then started_at else ${patch.startedAt ?? null}::timestamptz end,
      finished_at=case when ${patch.finishedAt === undefined} then finished_at else ${patch.finishedAt ?? null}::timestamptz end where id=${id}::uuid`.execute(this.db);
  }
  async patchStep(operationId: string, stepId: string, patch: StepPatch): Promise<void> {
    await sql`update operation_steps set state=${patch.state},attempt=coalesce(${patch.attempt ?? null},attempt),
      started_at=case when ${patch.startedAt === undefined} then started_at else ${patch.startedAt ?? null}::timestamptz end,
      finished_at=case when ${patch.finishedAt === undefined} then finished_at else ${patch.finishedAt ?? null}::timestamptz end,
      error_code=case when ${patch.errorCode === undefined} then error_code else ${patch.errorCode ?? null} end,
      error_message=case when ${patch.errorMessage === undefined} then error_message else ${patch.errorMessage ?? null} end
      where operation_id=${operationId}::uuid and id=${stepId}::uuid`.execute(this.db);
  }
  async appendOperationEvent(operationId: string, event: EventInput): Promise<OperationEvent> {
    type Row = Omit<OperationEvent, "createdAt"> & { createdAt: Date | string };
    const result = await sql<Row>`insert into operation_events (operation_id,level,code,message,step_key,created_at)
      values (${operationId}::uuid,${event.level},${event.code},${event.message},${event.stepKey ?? null},now()) returning *`.execute(this.db);
    const row = result.rows[0]!; return { ...row, id: Number(row.id), createdAt: iso(row.createdAt)! };
  }
  async listOperationEvents(operationId: string, after: number, limit: number): Promise<OperationEvent[]> {
    type Row = Omit<OperationEvent, "createdAt"> & { createdAt: Date | string };
    const result = await sql<Row>`select * from operation_events where operation_id=${operationId}::uuid and id>${after} order by id limit ${limit}`.execute(this.db);
    return result.rows.map((row) => ({ ...row, id: Number(row.id), createdAt: iso(row.createdAt)! }));
  }
  async getLatestSuccessfulPlan(environmentId: string, operationId: string): Promise<OperationRecord | null> {
    const operation = await this.getOperation(operationId);
    return operation?.environmentId === environmentId && (operation.kind === "plan" || operation.kind === "reconcile") && operation.state === "succeeded" && operation.plan ? operation : null;
  }

  async createEnrollment(item: EnrollmentRecord): Promise<void> { await sql`insert into node_enrollments (id,node_id,token_hash,expires_at,consumed_at,created_at) values (${item.id}::uuid,${item.nodeId}::uuid,${item.tokenHash},${item.expiresAt}::timestamptz,${item.consumedAt}::timestamptz,${item.createdAt}::timestamptz)`.execute(this.db); }
  async consumeEnrollment(tokenHash: string, identity: IdentityRecord): Promise<EnrollmentRecord | null> {
    return this.db.transaction().execute(async (trx) => {
      type Row = Omit<EnrollmentRecord, "expiresAt" | "consumedAt" | "createdAt"> & { expiresAt: Date | string; consumedAt: Date | string | null; createdAt: Date | string };
      const found = await sql<Row>`select * from node_enrollments where token_hash=${tokenHash} and consumed_at is null and expires_at>now() for update`.execute(trx);
      const row = found.rows[0]; if (!row) return null;
      await sql`update node_enrollments set consumed_at=now() where id=${row.id}::uuid`.execute(trx);
      await sql`insert into node_identities (id,node_id,token_hash,expires_at,revoked_at,created_at) values (${identity.id}::uuid,${row.nodeId}::uuid,${identity.tokenHash},${identity.expiresAt}::timestamptz,null,${identity.createdAt}::timestamptz)`.execute(trx);
      return { ...row, expiresAt: iso(row.expiresAt)!, consumedAt: new Date().toISOString(), createdAt: iso(row.createdAt)! };
    });
  }
  async findIdentityByToken(tokenHash: string): Promise<IdentityRecord | null> {
    type Row = Omit<IdentityRecord, "expiresAt" | "revokedAt" | "createdAt"> & { expiresAt: Date | string; revokedAt: Date | string | null; createdAt: Date | string };
    const result = await sql<Row>`select * from node_identities where token_hash=${tokenHash} and revoked_at is null and expires_at>now()`.execute(this.db);
    const row = result.rows[0]; return row ? { ...row, expiresAt: iso(row.expiresAt)!, revokedAt: iso(row.revokedAt), createdAt: iso(row.createdAt)! } : null;
  }
  async rotateIdentity(currentTokenHash: string, identity: IdentityRecord, overlapUntil: string): Promise<void> {
    await this.db.transaction().execute(async (trx) => {
      const found = await sql<{ nodeId: string }>`select node_id from node_identities where token_hash=${currentTokenHash} and revoked_at is null and expires_at>now() for update`.execute(trx);
      const nodeId = found.rows[0]?.nodeId; if (!nodeId) throw new Error("Current identity no longer exists");
      await sql`update node_identities set expires_at=${overlapUntil}::timestamptz where token_hash=${currentTokenHash}`.execute(trx);
      await sql`insert into node_identities (id,node_id,token_hash,expires_at,created_at) values (${identity.id}::uuid,${nodeId}::uuid,${identity.tokenHash},${identity.expiresAt}::timestamptz,${identity.createdAt}::timestamptz)`.execute(trx);
    });
  }
  async revokeNodeIdentities(nodeId: string): Promise<void> { await sql`update node_identities set revoked_at=now() where node_id=${nodeId}::uuid and revoked_at is null`.execute(this.db); }
  async saveObservation(nodeId: string, observation: ObservationRecord): Promise<void> {
    await this.db.transaction().execute(async (trx) => {
      await sql`insert into node_observations (node_id,generation,agent_version,capabilities,observation,observed_at) values (${nodeId}::uuid,${observation.generation},${observation.agentVersion},${JSON.stringify(observation.capabilities)}::jsonb,${JSON.stringify(observation.observation)}::jsonb,${observation.observedAt}::timestamptz)
        on conflict (node_id) do update set generation=excluded.generation,agent_version=excluded.agent_version,capabilities=excluded.capabilities,observation=excluded.observation,observed_at=excluded.observed_at`.execute(trx);
      await sql`update nodes set health='online',lifecycle=case when lifecycle='enrolling' then 'active' else lifecycle end,last_seen_at=${observation.observedAt}::timestamptz where id=${nodeId}::uuid`.execute(trx);
    });
  }
  async getObservation(nodeId: string): Promise<ObservationRecord | null> {
    type Row = Omit<ObservationRecord, "capabilities" | "observation" | "observedAt"> & { capabilities: unknown; observation: unknown; observedAt: Date | string };
    const row = (await sql<Row>`select * from node_observations where node_id=${nodeId}::uuid`.execute(this.db)).rows[0];
    return row ? { ...row, capabilities: json<ObservationRecord["capabilities"]>(row.capabilities), observation: json<Record<string, unknown>>(row.observation), observedAt: iso(row.observedAt)! } : null;
  }
  async getNode(id: string): Promise<NodeRecord | null> { const result = await sql<NodeRecord>`select * from nodes where id=${id}::uuid`.execute(this.db); return result.rows[0] ?? null; }
  async listNodes(environmentId: string): Promise<NodeRecord[]> { return (await sql<NodeRecord>`select * from nodes where environment_id=${environmentId}::uuid order by node_key`.execute(this.db)).rows; }
  async patchNode(id: string, patch: Partial<NodeRecord>): Promise<void> {
      await sql`update nodes set lifecycle=coalesce(${patch.lifecycle ?? null},lifecycle),health=coalesce(${patch.health ?? null},health),last_seen_at=case when ${patch.lastSeenAt === undefined} then last_seen_at else ${patch.lastSeenAt ?? null}::timestamptz end where id=${id}::uuid`.execute(this.db);
  }

  async createAgentCommand(input: AgentCommandCreate): Promise<AgentCommandRecord> {
    const id = randomUUID();
    const result = await sql<AgentCommandRecord>`insert into agent_commands (id,node_id,action_key,node_generation,kind,payload,state,attempt,deadline,created_at)
      values (${id}::uuid,${input.nodeId}::uuid,${input.actionKey},${input.nodeGeneration},${input.kind},${JSON.stringify(input.payload)}::jsonb,'pending',0,${input.deadline}::timestamptz,now())
      on conflict (node_id,action_key) do update set action_key=excluded.action_key returning *`.execute(this.db);
    return result.rows[0]!;
  }
  async listAgentCommands(nodeIds: string[], actionPrefix: string): Promise<AgentCommandRecord[]> {
    if (nodeIds.length === 0) return [];
    return (await sql<AgentCommandRecord>`select * from agent_commands where node_id = any(${sql.val(nodeIds)}::uuid[]) and action_key like ${`${actionPrefix}%`} order by created_at`.execute(this.db)).rows;
  }
  async expireAgentCommands(nodeIds: string[], actionPrefix: string, now: string): Promise<number> {
    if (nodeIds.length === 0) return 0;
    const result = await sql`update agent_commands set state='stale',lease_expires_at=null,error_code='task_deadline_expired',error_message='Agent task was not completed before its deadline'
      where node_id = any(${sql.val(nodeIds)}::uuid[]) and action_key like ${`${actionPrefix}%`} and deadline<=${now}::timestamptz and state in ('pending','leased')`.execute(this.db);
    return Number(result.numAffectedRows);
  }

  async claimAgentCommand(nodeId: string, now: string, leaseExpiresAt: string, leaseTokenHash: string, allowMutating: boolean): Promise<AgentCommandRecord | null> {
    type Row = AgentCommandRecord;
    const result = await sql<Row>`update agent_commands set state='leased',attempt=attempt+1,lease_token_hash=${leaseTokenHash},lease_expires_at=${leaseExpiresAt}::timestamptz
      where id=(select id from agent_commands where node_id=${nodeId}::uuid and deadline>${now}::timestamptz
        and (${allowMutating} or kind in ('InspectHost','CollectObservation','TailWorkloadLogs','RotateDeviceToken'))
        and (state='pending' or (state='leased' and lease_expires_at<${now}::timestamptz)) order by created_at for update skip locked limit 1)
      returning *`.execute(this.db);
    return result.rows[0] ?? null;
  }
  async appendAgentCommandEvent(commandId: string, nodeId: string, leaseTokenHash: string, sequence: number, level: "info" | "warning" | "error", message: string): Promise<boolean> {
    const valid = await sql`select id from agent_commands where id=${commandId}::uuid and node_id=${nodeId}::uuid and state='leased' and lease_token_hash=${leaseTokenHash} and lease_expires_at>now()`.execute(this.db);
    if (valid.rows.length === 0) return false;
    await sql`insert into agent_command_events (command_id,sequence,level,message,created_at) values (${commandId}::uuid,${sequence},${level},${message},now()) on conflict (command_id,sequence) do nothing`.execute(this.db);
    return true;
  }
  async completeAgentCommand(commandId: string, nodeId: string, leaseTokenHash: string, outcome: "succeeded" | "failed" | "stale", result: Record<string, unknown>, errorCode?: string, errorMessage?: string): Promise<boolean> {
    const updated = await sql`update agent_commands set state=${outcome},result=${JSON.stringify(result)}::jsonb,error_code=${errorCode ?? null},error_message=${errorMessage ?? null},lease_expires_at=null
      where id=${commandId}::uuid and node_id=${nodeId}::uuid and state='leased' and lease_token_hash=${leaseTokenHash} and lease_expires_at>now()`.execute(this.db);
    if (Number(updated.numAffectedRows) === 1) return true;
    const existing = await sql<{ state: string }>`select state from agent_commands where id=${commandId}::uuid and node_id=${nodeId}::uuid`.execute(this.db);
    return existing.rows[0]?.state === outcome;
  }

  async createConnection(item: ConnectionRecord): Promise<void> { await sql`insert into connections (id,kind,name,account_id,partition,principal_arn,validated_at,created_at) values (${item.id}::uuid,'aws',${item.name},${item.accountId},${item.partition},${item.principalArn},${item.validatedAt}::timestamptz,${item.createdAt}::timestamptz)`.execute(this.db); }
  async listConnections(): Promise<ConnectionRecord[]> { return (await sql<ConnectionRecord>`select id,name,account_id,partition,principal_arn,validated_at,created_at from connections where kind='aws' order by name`.execute(this.db)).rows; }
  async createWorkload(item: WorkloadRecord): Promise<void> { await sql`insert into workload_packages (id,name,description,created_at) values (${item.id}::uuid,${item.name},${item.description},${item.createdAt}::timestamptz)`.execute(this.db); }
  async listWorkloads(): Promise<WorkloadRecord[]> { return (await sql<WorkloadRecord>`select * from workload_packages order by name`.execute(this.db)).rows; }
  async createWorkloadVersion(item: WorkloadVersionRecord): Promise<void> { await sql`insert into workload_versions (id,workload_id,version,digest,compose_yaml,manifest,created_at) values (${item.id}::uuid,${item.workloadId}::uuid,${item.version},${item.digest},${item.composeYaml},${JSON.stringify(item.manifest)}::jsonb,${item.createdAt}::timestamptz)`.execute(this.db); }
  async listWorkloadVersions(workloadId: string): Promise<WorkloadVersionRecord[]> {
    type Row = Omit<WorkloadVersionRecord, "manifest"> & { manifest: WorkloadManifest };
    return (await sql<Row>`select * from workload_versions where workload_id=${workloadId}::uuid order by created_at desc`.execute(this.db)).rows.map((row) => ({ ...row, manifest: json<WorkloadManifest>(row.manifest) }));
  }
  async getWorkloadVersion(id: string): Promise<WorkloadVersionRecord | null> {
    type Row = Omit<WorkloadVersionRecord, "manifest"> & { manifest: WorkloadManifest };
    const row = (await sql<Row>`select * from workload_versions where id=${id}::uuid`.execute(this.db)).rows[0];
    return row ? { ...row, manifest: json<WorkloadManifest>(row.manifest) } : null;
  }
  async getNetworkAuthority(environmentId: string): Promise<NetworkAuthorityRecord | null> { return (await sql<NetworkAuthorityRecord>`select * from network_authorities where environment_id=${environmentId}::uuid`.execute(this.db)).rows[0] ?? null; }
  async saveNetworkAuthority(item: NetworkAuthorityRecord): Promise<void> { await sql`insert into network_authorities (environment_id,ca_certificate,encrypted_private_key,nonce,auth_tag,key_version,created_at,expires_at) values (${item.environmentId}::uuid,${item.caCertificate},${item.encryptedPrivateKey},${item.nonce},${item.authTag},${item.keyVersion},${item.createdAt}::timestamptz,${item.expiresAt}::timestamptz) on conflict (environment_id) do nothing`.execute(this.db); }
  async allocateNetworkMembership(environmentId: string, nodeId: string, cidr: string, publicKey: string): Promise<NetworkMembershipRecord> {
    return this.db.transaction().execute(async (trx) => {
      await sql`select pg_advisory_xact_lock(hashtext(${environmentId}))`.execute(trx);
      const current = (await sql<NetworkMembershipRecord>`select environment_id,node_id,host(overlay_address)||'/'||masklen(overlay_address) as overlay_address,public_key,certificate_serial,certificate_expires_at,status from network_memberships where node_id=${nodeId}::uuid`.execute(trx)).rows[0]; if (current) return current;
      const [base, prefixRaw] = cidr.split("/"); const prefix = Number(prefixRaw); if (prefix < 16 || prefix > 29) throw new Error("Nebula network prefix must be between /16 and /29");
      const parts = base!.split(".").map(Number); const baseInt = ((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!; const capacity = 2 ** (32 - prefix) - 2;
      const used = new Set((await sql<{ address: string }>`select host(overlay_address) as address from network_memberships where environment_id=${environmentId}::uuid`.execute(trx)).rows.map(({ address }) => address));
      let address = ""; for (let offset = 2; offset <= capacity; offset += 1) { const value = (baseInt + offset) >>> 0; const candidate = `${value >>> 24}.${(value >>> 16) & 255}.${(value >>> 8) & 255}.${value & 255}`; if (!used.has(candidate)) { address = `${candidate}/${prefix}`; break; } }
      if (!address) throw new Error("Nebula network has no available overlay address");
      return (await sql<NetworkMembershipRecord>`insert into network_memberships (id,environment_id,node_id,overlay_address,public_key,status) values (${randomUUID()}::uuid,${environmentId}::uuid,${nodeId}::uuid,${address}::inet,${publicKey},'allocated') returning environment_id,node_id,host(overlay_address)||'/'||masklen(overlay_address) as overlay_address,public_key,certificate_serial,certificate_expires_at,status`.execute(trx)).rows[0]!;
    });
  }
  async listNetworkMemberships(environmentId: string): Promise<NetworkMembershipRecord[]> { return (await sql<NetworkMembershipRecord>`select environment_id,node_id,host(overlay_address)||'/'||masklen(overlay_address) as overlay_address,public_key,certificate_serial,certificate_expires_at,status from network_memberships where environment_id=${environmentId}::uuid`.execute(this.db)).rows; }
  async createCredential(item: CredentialRecord): Promise<void> { await sql`insert into credentials (id,name,kind,registry,encrypted_payload,nonce,auth_tag,key_version,created_at,updated_at) values (${item.id}::uuid,${item.name},${item.kind},${item.registry},decode(${item.encryptedPayload},'base64'),decode(${item.nonce},'base64'),decode(${item.authTag},'base64'),${item.keyVersion},${item.createdAt}::timestamptz,${item.updatedAt}::timestamptz)`.execute(this.db); }
  async listCredentials(): Promise<CredentialPublicRecord[]> { return (await sql<CredentialPublicRecord>`select id,name,kind,registry,created_at,updated_at from credentials order by name`.execute(this.db)).rows; }
  async getCredential(id: string): Promise<CredentialRecord | null> { return (await sql<CredentialRecord>`select id,name,kind,registry,encode(encrypted_payload,'base64') as encrypted_payload,encode(nonce,'base64') as nonce,encode(auth_tag,'base64') as auth_tag,key_version,created_at,updated_at from credentials where id=${id}::uuid`.execute(this.db)).rows[0] ?? null; }
  async updateCredential(item: CredentialRecord): Promise<void> { await sql`update credentials set name=${item.name},kind=${item.kind},registry=${item.registry},encrypted_payload=decode(${item.encryptedPayload},'base64'),nonce=decode(${item.nonce},'base64'),auth_tag=decode(${item.authTag},'base64'),key_version=${item.keyVersion},updated_at=${item.updatedAt}::timestamptz where id=${item.id}::uuid`.execute(this.db); }
  async deleteCredential(id: string): Promise<boolean> { return Number((await sql`delete from credentials where id=${id}::uuid`.execute(this.db)).numAffectedRows) === 1; }
  async heartbeatWorker(instanceId: string, startedAt: string, concurrency: number): Promise<void> { await sql`insert into worker_instances (instance_id,started_at,last_seen_at,concurrency) values (${instanceId}::uuid,${startedAt}::timestamptz,now(),${concurrency}) on conflict(instance_id) do update set last_seen_at=now(),concurrency=excluded.concurrency`.execute(this.db); }
  async hasFreshWorker(maxAgeSeconds: number): Promise<boolean> { return (await sql<{ fresh: boolean }>`select exists(select 1 from worker_instances where last_seen_at > now() - (${maxAgeSeconds} * interval '1 second')) as fresh`.execute(this.db)).rows[0]?.fresh === true; }
  async ready(): Promise<boolean> {
    const result = await sql<{ appSchema: string | null; queueReady: boolean }>`select to_regclass('public.environments')::text as app_schema,
      exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='graphile_worker' and p.proname='add_job') as queue_ready`.execute(this.db);
    return result.rows[0]?.appSchema === "environments" && result.rows[0]?.queueReady === true;
  }
  async close(): Promise<void> { await this.db.destroy(); }
}
