import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import type { Credential, CredentialInput } from "@infractory/contracts";
import type { ControlPlaneStore } from "../db/store.js";
import type { CredentialRecord } from "../domain/models.js";
import { invalid, notFound } from "../domain/errors.js";

type SecretPayload = { secret: string; username?: string };

export class CredentialService {
  constructor(private readonly store: ControlPlaneStore, private readonly key: Buffer) {
    if (key.length !== 32) throw new Error("Credential encryption requires a 32-byte key");
  }

  private aad(id: string, kind: CredentialInput["kind"], registry: string | null, keyVersion: number): Buffer {
    return Buffer.from(`infractory-credential:${id}:${kind}:${registry ?? ""}:${keyVersion}`, "utf8");
  }

  private encrypt(id: string, input: CredentialInput, createdAt: string): CredentialRecord {
    const keyVersion = 1;
    const nonce = randomBytes(12);
    const registry = input.kind === "registry" ? normalizeRegistry(input.registry) : null;
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(this.aad(id, input.kind, registry, keyVersion));
    const payload: SecretPayload = input.kind === "registry"
      ? { secret: input.secret, ...(input.username === undefined ? {} : { username: input.username }) }
      : { secret: input.secret };
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
    const now = new Date().toISOString();
    return {
      id, name: input.name.trim(), kind: input.kind, registry,
      encryptedPayload: encrypted.toString("base64"), nonce: nonce.toString("base64"), authTag: cipher.getAuthTag().toString("base64"),
      keyVersion, createdAt, updatedAt: now
    };
  }

  private decrypt(record: CredentialRecord): SecretPayload {
    try {
      const decipher = createDecipheriv("aes-256-gcm", this.key, Buffer.from(record.nonce, "base64"));
      decipher.setAAD(this.aad(record.id, record.kind, record.registry, record.keyVersion));
      decipher.setAuthTag(Buffer.from(record.authTag, "base64"));
      const clear = Buffer.concat([decipher.update(Buffer.from(record.encryptedPayload, "base64")), decipher.final()]);
      const value = JSON.parse(clear.toString("utf8")) as Partial<SecretPayload>;
      if (typeof value.secret !== "string") throw new Error("invalid credential payload");
      return { secret: value.secret, ...(typeof value.username === "string" ? { username: value.username } : {}) };
    } catch {
      throw invalid("credential_decryption_failed", `Credential '${record.name}' cannot be decrypted with the configured application key`);
    }
  }

  private public(record: CredentialRecord): Credential {
    return { id: record.id, name: record.name, kind: record.kind, registry: record.registry, createdAt: record.createdAt, updatedAt: record.updatedAt };
  }

  async create(input: CredentialInput): Promise<Credential> {
    const id = randomUUID(); const createdAt = new Date().toISOString(); const record = this.encrypt(id, input, createdAt);
    await this.store.createCredential(record); return this.public(record);
  }
  list(): Promise<Credential[]> { return this.store.listCredentials(); }
  async get(id: string): Promise<Credential> { const record = await this.store.getCredential(id); if (!record) throw notFound("Credential"); return this.public(record); }
  async update(id: string, input: CredentialInput): Promise<Credential> {
    const current = await this.store.getCredential(id); if (!current) throw notFound("Credential");
    const record = this.encrypt(id, input, current.createdAt); await this.store.updateCredential(record); return this.public(record);
  }
  async delete(id: string): Promise<void> { if (!await this.store.deleteCredential(id)) throw notFound("Credential"); }

  async resolveOpaque(id: string): Promise<string> {
    const record = await this.store.getCredential(id); if (!record) throw notFound("Credential");
    if (record.kind !== "opaque") throw invalid("credential_kind_mismatch", `Credential '${record.name}' is not an opaque workload secret`);
    return this.decrypt(record).secret;
  }
  async resolveRegistry(id: string, registry: string): Promise<{ username?: string; secret: string }> {
    const record = await this.store.getCredential(id); if (!record) throw notFound("Credential");
    if (record.kind !== "registry" || record.registry !== normalizeRegistry(registry)) throw invalid("credential_scope_mismatch", `Credential '${record.name}' is not scoped to registry '${registry}'`);
    return this.decrypt(record);
  }
}

export function normalizeRegistry(value: string): string {
  let url: URL;
  try { url = new URL(`https://${value}`); } catch { throw invalid("invalid_registry", "Registry must be a hostname with an optional port"); }
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash || !url.hostname || value.includes("/")) throw invalid("invalid_registry", "Registry must be a hostname with an optional port");
  return url.host.toLowerCase();
}
