import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import type { EnvironmentSpec, NebulaCertificateRequest, NebulaCertificateResponse } from "@infractory/contracts";
import type { AppConfig } from "../config.js";
import type { ControlPlaneStore } from "../db/store.js";
import { conflict, notFound } from "../domain/errors.js";

type CreateCaResponse = { caCertificate: string; caPrivateKey: string };
type SignResponse = { certificate: string; fingerprint: string };

export class NetworkService {
  constructor(private readonly store: ControlPlaneStore, private readonly config: AppConfig) {}
  private encrypt(plaintext: string): { encryptedPrivateKey: string; nonce: string; authTag: string } {
    const nonce = randomBytes(12); const cipher = createCipheriv("aes-256-gcm", this.config.encryptionKey, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return { encryptedPrivateKey: ciphertext.toString("base64"), nonce: nonce.toString("base64"), authTag: cipher.getAuthTag().toString("base64") };
  }
  private decrypt(ciphertext: string, nonce: string, authTag: string): string {
    const decipher = createDecipheriv("aes-256-gcm", this.config.encryptionKey, Buffer.from(nonce, "base64"));
    decipher.setAuthTag(Buffer.from(authTag, "base64")); return Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64")), decipher.final()]).toString("utf8");
  }
  private async helper<T>(request: Record<string, unknown>): Promise<T> {
    if (!this.config.pkiHelperPath) throw conflict("pki_helper_unavailable", "INFRACTORY_PKI_HELPER_PATH is required for Nebula certificate operations");
    const stdout = await new Promise<string>((resolve, reject) => {
      const child = spawn(this.config.pkiHelperPath!, [], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
      const output: Buffer[] = []; const errors: Buffer[] = []; let size = 0;
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("PKI helper timed out")); }, 15_000);
      child.stdout.on("data", (chunk: Buffer) => { size += chunk.length; if (size > 1024 * 1024) { child.kill("SIGKILL"); reject(new Error("PKI helper output exceeded limit")); } else output.push(chunk); });
      child.stderr.on("data", (chunk: Buffer) => { if (errors.reduce((total, value) => total + value.length, 0) < 8192) errors.push(chunk); });
      child.on("error", reject);
      child.on("close", (code) => { clearTimeout(timer); code === 0 ? resolve(Buffer.concat(output).toString("utf8")) : reject(new Error(`PKI helper failed: ${Buffer.concat(errors).toString("utf8").slice(0, 8192)}`)); });
      child.stdin.end(JSON.stringify(request));
    });
    return JSON.parse(stdout) as T;
  }
  async ensureAuthority(environmentId: string, spec: EnvironmentSpec): Promise<{ caCertificate: string }> {
    const current = await this.store.getNetworkAuthority(environmentId); if (current) return { caCertificate: current.caCertificate };
    const now = new Date(); const expiresAt = new Date(now.getTime() + 365 * 24 * 60 * 60_000);
    const generated = await this.helper<CreateCaResponse>({ kind: "createCa", name: `infractory-${environmentId}`, network: spec.network.cidr, notBefore: new Date(now.getTime() - 5 * 60_000).toISOString(), notAfter: expiresAt.toISOString() });
    if (!generated.caCertificate || !generated.caPrivateKey) throw new Error("PKI helper returned incomplete CA material");
    const encrypted = this.encrypt(generated.caPrivateKey);
    await this.store.saveNetworkAuthority({ environmentId, caCertificate: generated.caCertificate, ...encrypted, keyVersion: 1, createdAt: now.toISOString(), expiresAt: expiresAt.toISOString() });
    return { caCertificate: generated.caCertificate };
  }
  async issue(nodeId: string, input: NebulaCertificateRequest): Promise<NebulaCertificateResponse> {
    const node = await this.store.getNode(nodeId); if (!node || node.environmentId !== input.environmentId) throw notFound("Node");
    const revision = await this.store.getRevision(input.environmentId); if (!revision) throw notFound("Environment revision");
    const nodeSpec = revision.spec.nodes.find(({ key }) => key === node.nodeKey); if (!nodeSpec) throw notFound("Node specification");
    const authority = await this.store.getNetworkAuthority(input.environmentId); if (!authority) throw conflict("network_authority_unavailable", "Nebula authority has not been created by apply");
    const membership = await this.store.allocateNetworkMembership(input.environmentId, nodeId, revision.spec.network.cidr, input.publicKey);
    if (membership.publicKey !== input.publicKey) throw conflict("nebula_key_changed", "Node identity key changed; explicit certificate rotation is required");
    const groups = input.requestedGroups.filter((group) => nodeSpec.roles.includes(group)); const now = new Date(); const expiresAt = new Date(Math.min(new Date(authority.expiresAt).getTime(), now.getTime() + 30 * 24 * 60 * 60_000));
    const signed = await this.helper<SignResponse>({ kind: "sign", caCertificate: authority.caCertificate, caPrivateKey: this.decrypt(authority.encryptedPrivateKey, authority.nonce, authority.authTag), publicKey: input.publicKey, name: node.name, networks: [membership.overlayAddress], groups, notBefore: new Date(now.getTime() - 5 * 60_000).toISOString(), notAfter: expiresAt.toISOString() });
    if (!signed.certificate) throw new Error("PKI helper returned no host certificate");
    return { certificate: signed.certificate, caCertificate: authority.caCertificate, overlayAddress: membership.overlayAddress, expiresAt: expiresAt.toISOString(), blocklist: [] };
  }
  renderConfig(environmentId: string, spec: EnvironmentSpec, nodeKey: string, lighthouseEndpoints: Record<string, string>): string {
    const lighthouse = spec.network.lighthouseNodeKeys.includes(nodeKey);
    const hosts = Object.entries(lighthouseEndpoints).map(([overlay, endpoint]) => `  \"${overlay}\": [\"${endpoint}:4242\"]`).join("\n");
    const hostList = lighthouse ? "[]" : `[${Object.keys(lighthouseEndpoints).map((address) => `\"${address}\"`).join(", ")}]`;
    return `pki:\n  ca: /var/lib/infractory/placeholder/ca.crt\n  cert: /var/lib/infractory/placeholder/host.crt\n  key: /var/lib/infractory/placeholder/host.key\nstatic_host_map:\n${hosts || "  {}"}\nlighthouse:\n  am_lighthouse: ${lighthouse}\n  hosts: ${hostList}\nlisten:\n  host: 0.0.0.0\n  port: 4242\npunchy:\n  punch: true\nfirewall:\n  outbound:\n    - port: any\n      proto: any\n      host: any\n  inbound:\n    - port: any\n      proto: icmp\n      host: any\n`;
  }
}
