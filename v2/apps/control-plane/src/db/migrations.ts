import { sql, type Kysely, type Migration } from "kysely";

const initial: Migration = {
  async up(db: Kysely<unknown>): Promise<void> {
    await sql`create extension if not exists pgcrypto`.execute(db);
    await sql`
      create table environments (
        id uuid primary key, name text not null, lifecycle text not null, health text not null,
        desired_revision integer not null check (desired_revision > 0), applied_revision integer,
        expires_at timestamptz, created_at timestamptz not null, updated_at timestamptz not null,
        etag text not null,
        constraint environments_lifecycle check (lifecycle in ('draft','applying','active','apply_failed','destroying','destroyed','destroy_failed','abandoned')),
        constraint environments_health check (health in ('unknown','healthy','degraded','unreachable'))
      );
      create table environment_revisions (
        id uuid primary key, environment_id uuid not null references environments(id) on delete restrict,
        revision integer not null check (revision > 0), digest char(64) not null,
        spec jsonb not null, created_at timestamptz not null,
        unique(environment_id, revision), unique(environment_id, digest)
      );
      create table connections (
        id uuid primary key, kind text not null check (kind = 'aws'), name text not null,
        account_id text not null, partition text not null, principal_arn text not null,
        validated_at timestamptz not null, created_at timestamptz not null,
        unique(kind, name)
      );
      create table credentials (
        id uuid primary key, name text not null unique, kind text not null,
        ciphertext bytea not null, nonce bytea not null, key_version integer not null,
        created_at timestamptz not null, updated_at timestamptz not null
      );
      create table cloud_stacks (
        id uuid primary key, environment_id uuid not null unique references environments(id) on delete restrict,
        stack_name text not null unique, program_version text not null, provider_version text not null,
        outputs jsonb not null default '{}'::jsonb, last_operation jsonb,
        created_at timestamptz not null, updated_at timestamptz not null
      );
      create table nodes (
        id uuid primary key, environment_id uuid not null references environments(id) on delete restrict,
        node_key text not null, name text not null, origin text not null check (origin in ('aws','adopted')),
        generation integer not null check (generation >= 0),
        lifecycle text not null check (lifecycle in ('pending','enrolling','active','removing','removed','detached')),
        health text not null check (health in ('unknown','online','degraded','offline')),
        last_seen_at timestamptz, unique(environment_id, node_key)
      );
      create table node_enrollments (
        id uuid primary key, node_id uuid not null references nodes(id) on delete restrict,
        token_hash char(64) not null unique, expires_at timestamptz not null,
        consumed_at timestamptz, created_at timestamptz not null
      );
      create table node_identities (
        id uuid primary key, node_id uuid not null references nodes(id) on delete restrict,
        token_hash char(64) not null unique, expires_at timestamptz not null,
        revoked_at timestamptz, created_at timestamptz not null
      );
      create table node_observations (
        node_id uuid primary key references nodes(id) on delete restrict,
        generation integer not null, agent_version text not null, capabilities jsonb not null,
        observation jsonb not null, observed_at timestamptz not null
      );
      create table network_memberships (
        id uuid primary key, environment_id uuid not null references environments(id) on delete restrict,
        node_id uuid not null unique references nodes(id) on delete restrict,
        overlay_address inet not null, certificate_serial text, certificate_expires_at timestamptz,
        public_key text, status text not null, unique(environment_id, overlay_address)
      );
      create table workload_packages (
        id uuid primary key, name text not null unique, description text not null, created_at timestamptz not null
      );
      create table workload_versions (
        id uuid primary key, workload_id uuid not null references workload_packages(id) on delete restrict,
        version text not null, digest char(64) not null, compose_yaml text not null,
        manifest jsonb not null, created_at timestamptz not null,
        unique(workload_id, version), unique(workload_id, digest)
      );
      create table deployments (
        id uuid primary key, environment_id uuid not null references environments(id) on delete restrict,
        node_id uuid not null references nodes(id) on delete restrict,
        workload_version_id uuid not null references workload_versions(id) on delete restrict,
        deployment_key text not null, desired_generation integer not null, applied_generation integer,
        desired_state text not null check (desired_state in ('running','stopped')),
        health text not null check (health in ('unknown','healthy','degraded','unreachable')),
        unique(environment_id, deployment_key)
      );
      create table operations (
        id uuid primary key, environment_id uuid not null references environments(id) on delete restrict,
        kind text not null check (kind in ('plan','apply','reconcile','destroy','abandon')),
        state text not null check (state in ('queued','running','waiting','succeeded','blocked','failed','needs_reconciliation','cancelling','cancelled')),
        revision integer not null, idempotency_key text not null,
        retry_of_operation_id uuid references operations(id) on delete restrict,
        plan_operation_id uuid references operations(id) on delete restrict,
        result jsonb, plan jsonb, created_at timestamptz not null,
        started_at timestamptz, finished_at timestamptz,
        unique(environment_id, idempotency_key)
      );
      create unique index operations_one_mutation on operations(environment_id)
        where state in ('queued','running','waiting','cancelling') and kind <> 'plan';
      create table operation_steps (
        id uuid primary key, operation_id uuid not null references operations(id) on delete restrict,
        key text not null, title text not null, position integer not null,
        state text not null check (state in ('pending','running','waiting','succeeded','failed','skipped','cancelled')),
        attempt integer not null default 0, started_at timestamptz, finished_at timestamptz,
        error_code text, error_message text, unique(operation_id, key), unique(operation_id, position)
      );
      create table operation_events (
        id bigserial primary key, operation_id uuid not null references operations(id) on delete restrict,
        level text not null check (level in ('info','warning','error')), code text not null,
        message text not null, step_key text, created_at timestamptz not null
      );
      create index operation_events_stream on operation_events(operation_id, id);
      create table agent_commands (
        id uuid primary key, node_id uuid not null references nodes(id) on delete restrict,
        action_key text not null, node_generation integer not null, kind text not null, payload jsonb not null,
        state text not null check (state in ('pending','leased','succeeded','failed','stale')),
        attempt integer not null default 0, lease_token_hash char(64), lease_expires_at timestamptz,
        deadline timestamptz not null, result jsonb, error_code text, error_message text,
        created_at timestamptz not null, unique(node_id, action_key)
      );
      create table agent_command_events (
        id bigserial primary key, command_id uuid not null references agent_commands(id) on delete restrict,
        sequence integer not null, level text not null check (level in ('info','warning','error')),
        message text not null, created_at timestamptz not null, unique(command_id, sequence)
      );
    `.execute(db);
  },
  async down(): Promise<void> {
    throw new Error("Forward-only migrations cannot be rolled back");
  }
};

const networkAuthorities: Migration = {
  async up(db: Kysely<unknown>): Promise<void> {
    await sql`create table network_authorities (
      environment_id uuid primary key references environments(id) on delete restrict,
      ca_certificate text not null, encrypted_private_key text not null, nonce text not null,
      auth_tag text not null, key_version integer not null, created_at timestamptz not null, expires_at timestamptz not null
    )`.execute(db);
  },
  async down(): Promise<void> { throw new Error("Forward-only migrations cannot be rolled back"); }
};

const credentialsAndWorkers: Migration = {
  async up(db: Kysely<unknown>): Promise<void> {
    await sql`
      alter table credentials add column registry text;
      alter table credentials rename column ciphertext to encrypted_payload;
      alter table credentials add column auth_tag bytea not null;
      create table worker_instances (
        instance_id uuid primary key, started_at timestamptz not null, last_seen_at timestamptz not null,
        concurrency integer not null check (concurrency between 1 and 64)
      );
    `.execute(db);
  },
  async down(): Promise<void> { throw new Error("Forward-only migrations cannot be rolled back"); }
};

const reusableEnvironmentRevisionDigests: Migration = {
  async up(db: Kysely<unknown>): Promise<void> {
    await sql`alter table environment_revisions drop constraint environment_revisions_environment_id_digest_key`.execute(db);
  },
  async down(): Promise<void> { throw new Error("Forward-only migrations cannot be rolled back"); }
};

export const migrations: Record<string, Migration> = {
  "001_initial": initial,
  "002_network_authorities": networkAuthorities,
  "003_credentials_workers": credentialsAndWorkers,
  "004_reusable_environment_revision_digests": reusableEnvironmentRevisionDigests
};
