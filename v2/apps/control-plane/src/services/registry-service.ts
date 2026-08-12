import { createHash } from "node:crypto";
import type { CredentialService } from "./credential-service.js";
import { normalizeRegistry } from "./credential-service.js";

type Fetch = typeof globalThis.fetch;
type ParsedImage = { registry: string; repository: string; reference: string; digestPinned: boolean };
const ACCEPT = [
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
  "application/vnd.docker.distribution.manifest.list.v2+json"
].join(", ");

export class RegistryResolutionError extends Error {
  constructor(message: string) { super(message); this.name = "RegistryResolutionError"; }
}

export class RegistryService {
  constructor(
    private readonly credentials: CredentialService,
    private readonly fetcher: Fetch = globalThis.fetch,
    private readonly timeoutMs = 8_000
  ) {}

  async resolve(image: string, credentialId?: string): Promise<string> {
    const parsed = parseImage(image);
    if (parsed.digestPinned) return `${parsed.registry}/${parsed.repository}@${parsed.reference}`;
    const auth = credentialId ? await this.credentials.resolveRegistry(credentialId, parsed.registry) : undefined;
    const endpointHost = parsed.registry === "docker.io" ? "registry-1.docker.io" : parsed.registry;
    const url = `https://${endpointHost}/v2/${parsed.repository}/manifests/${encodeURIComponent(parsed.reference)}`;
    const headers = new Headers({ Accept: ACCEPT });
    if (auth) headers.set("Authorization", `Basic ${Buffer.from(`${auth.username ?? ""}:${auth.secret}`).toString("base64")}`);
    let response = await this.request(url, headers);
    if (response.status === 401) {
      const challenge = response.headers.get("www-authenticate");
      await response.body?.cancel();
      if (!challenge?.toLowerCase().startsWith("bearer ")) throw new RegistryResolutionError(`Registry '${parsed.registry}' rejected the supplied credentials`);
      const token = await this.bearerToken(challenge, auth);
      headers.set("Authorization", `Bearer ${token}`);
      response = await this.request(url, headers);
    }
    if (!response.ok) { await response.body?.cancel(); throw new RegistryResolutionError(`Registry '${parsed.registry}' returned HTTP ${response.status} while resolving '${image}'`); }
    const body = Buffer.from(await response.arrayBuffer());
    if (body.length > 5 * 1024 * 1024) throw new RegistryResolutionError(`Manifest for '${image}' exceeds the 5 MiB planning limit`);
    const header = response.headers.get("docker-content-digest")?.toLowerCase();
    const digest = header && /^sha256:[a-f0-9]{64}$/.test(header) ? header : `sha256:${createHash("sha256").update(body).digest("hex")}`;
    return `${parsed.registry}/${parsed.repository}@${digest}`;
  }

  private async request(url: string, headers: Headers): Promise<Response> {
    try { return await this.fetcher(url, { method: "GET", headers, redirect: "error", signal: AbortSignal.timeout(this.timeoutMs) }); }
    catch (error) { throw new RegistryResolutionError(`Registry request failed: ${error instanceof Error ? error.message : "network error"}`); }
  }

  private async bearerToken(challenge: string, auth?: { username?: string; secret: string }): Promise<string> {
    const values = Object.fromEntries([...challenge.slice(7).matchAll(/([A-Za-z]+)="([^"]*)"/g)].map((match) => [match[1]!.toLowerCase(), match[2]!]));
    if (!values["realm"]) throw new RegistryResolutionError("Registry bearer challenge omitted its token realm");
    let realm: URL;
    try { realm = new URL(values["realm"]); } catch { throw new RegistryResolutionError("Registry returned an invalid token realm"); }
    if (realm.protocol !== "https:" || realm.username || realm.password || realm.hash) throw new RegistryResolutionError("Registry token realm must be an HTTPS URL without embedded credentials");
    if (values["service"]) realm.searchParams.set("service", values["service"]);
    if (values["scope"]) realm.searchParams.set("scope", values["scope"]);
    const headers = new Headers({ Accept: "application/json" });
    if (auth) headers.set("Authorization", `Basic ${Buffer.from(`${auth.username ?? ""}:${auth.secret}`).toString("base64")}`);
    const response = await this.request(realm.toString(), headers);
    if (!response.ok) { await response.body?.cancel(); throw new RegistryResolutionError(`Registry token service returned HTTP ${response.status}`); }
    const body = Buffer.from(await response.arrayBuffer());
    if (body.length > 64 * 1024) throw new RegistryResolutionError("Registry token response exceeds the 64 KiB limit");
    let value: unknown; try { value = JSON.parse(body.toString("utf8")); } catch { throw new RegistryResolutionError("Registry token service returned invalid JSON"); }
    const token = (value as { token?: unknown; access_token?: unknown }).token ?? (value as { access_token?: unknown }).access_token;
    if (typeof token !== "string" || token.length < 1 || token.length > 16_384) throw new RegistryResolutionError("Registry token service did not return a valid token");
    return token;
  }
}

export function parseImage(image: string): ParsedImage {
  const value = image.trim();
  if (!value || value.includes(" ") || value.includes("://")) throw new RegistryResolutionError(`Invalid OCI image reference '${image}'`);
  const at = value.lastIndexOf("@");
  const pathPart = at >= 0 ? value.slice(0, at) : value;
  const digestPart = at >= 0 ? value.slice(at + 1).toLowerCase() : null;
  if (digestPart !== null && !/^sha256:[a-f0-9]{64}$/.test(digestPart)) throw new RegistryResolutionError(`Image '${image}' uses an unsupported digest`);
  const segments = pathPart.split("/");
  const explicitRegistry = segments.length > 1 && (segments[0]!.includes(".") || segments[0]!.includes(":") || segments[0] === "localhost");
  const registry = normalizeRegistry(explicitRegistry ? segments.shift()! : "docker.io");
  let repositoryWithTag = segments.join("/");
  if (!repositoryWithTag) throw new RegistryResolutionError(`Invalid OCI image reference '${image}'`);
  if (!explicitRegistry && !repositoryWithTag.includes("/")) repositoryWithTag = `library/${repositoryWithTag}`;
  const lastSlash = repositoryWithTag.lastIndexOf("/"); const lastColon = repositoryWithTag.lastIndexOf(":");
  const tag = digestPart === null && lastColon > lastSlash ? repositoryWithTag.slice(lastColon + 1) : "latest";
  const repository = digestPart === null && lastColon > lastSlash ? repositoryWithTag.slice(0, lastColon) : repositoryWithTag;
  if (!/^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/.test(repository) || !/^[\w][\w.-]{0,127}$/.test(tag)) throw new RegistryResolutionError(`Invalid OCI image reference '${image}'`);
  return { registry, repository, reference: digestPart ?? tag, digestPinned: digestPart !== null };
}
