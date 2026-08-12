import { createHash, randomBytes } from "node:crypto";

export type AppConfig = {
  host: string;
  port: number;
  databaseUrl?: string;
  executionMode: "inline" | "graphile";
  infrastructureMode: "fake" | "pulumi";
  publicUrl: string;
  tokenPepper: string;
  pulumiBackendUrl?: string;
  agentArtifactDirectory?: string;
  agentAmd64Sha256?: string;
  pkiHelperPath?: string;
  encryptionKey: Buffer;
  workerConcurrency: number;
  pulumiConcurrency: number;
};

function enumValue<T extends string>(value: string | undefined, allowed: readonly T[], fallback: T): T {
  const candidate = value ?? fallback;
  if (!allowed.includes(candidate as T)) throw new Error(`Invalid configuration value: ${candidate}`);
  return candidate as T;
}

function boundedInteger(value: string | undefined, fallback: number, name: string, maximum: number): number {
  const parsed = Number.parseInt(value ?? String(fallback), 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  return parsed;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const executionMode = enumValue(env.INFRACTORY_EXECUTION_MODE, ["inline", "graphile"] as const, env.NODE_ENV === "test" ? "inline" : "graphile");
  const infrastructureMode = enumValue(env.INFRACTORY_INFRASTRUCTURE_MODE, ["fake", "pulumi"] as const, "fake");
  const port = Number.parseInt(env.PORT ?? "8080", 10);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be a valid TCP port");
  if (executionMode === "graphile" && !env.DATABASE_URL) throw new Error("DATABASE_URL is required in graphile mode");
  if (infrastructureMode === "pulumi" && !env.PULUMI_BACKEND_URL) throw new Error("PULUMI_BACKEND_URL is required in pulumi mode");
  if (infrastructureMode === "pulumi" && (!env.INFRACTORY_AGENT_ARTIFACT_DIRECTORY || !/^[a-f0-9]{64}$/.test(env.INFRACTORY_AGENT_AMD64_SHA256 ?? ""))) throw new Error("INFRACTORY_AGENT_ARTIFACT_DIRECTORY and INFRACTORY_AGENT_AMD64_SHA256 are required in pulumi mode");
  const publicUrl = env.INFRACTORY_PUBLIC_URL ?? `http://localhost:${port}`;
  let parsedPublicUrl: URL;
  try { parsedPublicUrl = new URL(publicUrl); } catch { throw new Error("INFRACTORY_PUBLIC_URL must be an absolute URL"); }
  if (parsedPublicUrl.username || parsedPublicUrl.password || parsedPublicUrl.search || parsedPublicUrl.hash || parsedPublicUrl.pathname !== "/") {
    throw new Error("INFRACTORY_PUBLIC_URL must be an origin without credentials, path, query, or fragment");
  }
  const loopbackDevelopmentUrl = infrastructureMode === "fake" && parsedPublicUrl.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(parsedPublicUrl.hostname);
  if (parsedPublicUrl.protocol !== "https:" && !loopbackDevelopmentUrl) throw new Error("INFRACTORY_PUBLIC_URL must use HTTPS except for the loopback fake-infrastructure development mode");
  const encryptionKeyValue = env.APP_ENCRYPTION_KEY ?? env.INFRACTORY_ENCRYPTION_KEY;
  if ((infrastructureMode === "pulumi" || env.NODE_ENV === "production") && !encryptionKeyValue) throw new Error("APP_ENCRYPTION_KEY is required in Pulumi and production modes");
  const encryptionKey = encryptionKeyValue ? Buffer.from(encryptionKeyValue, "base64") : Buffer.from(createHash("sha256").update("development-only-infractory-key").digest());
  if (encryptionKey.length !== 32) throw new Error("APP_ENCRYPTION_KEY must be a base64-encoded 32-byte key");
  if (env.NODE_ENV === "production" && (!env.INFRACTORY_TOKEN_PEPPER || env.INFRACTORY_TOKEN_PEPPER.length < 32)) {
    throw new Error("INFRACTORY_TOKEN_PEPPER must contain at least 32 characters in production");
  }
  return {
    host: env.HOST ?? "0.0.0.0",
    port,
    ...(env.DATABASE_URL ? { databaseUrl: env.DATABASE_URL } : {}),
    executionMode,
    infrastructureMode,
    publicUrl,
    tokenPepper: env.INFRACTORY_TOKEN_PEPPER ?? randomBytes(32).toString("hex"),
    ...(env.PULUMI_BACKEND_URL ? { pulumiBackendUrl: env.PULUMI_BACKEND_URL } : {})
    ,...(env.INFRACTORY_AGENT_ARTIFACT_DIRECTORY ? { agentArtifactDirectory: env.INFRACTORY_AGENT_ARTIFACT_DIRECTORY } : {})
    ,...(env.INFRACTORY_AGENT_AMD64_SHA256 ? { agentAmd64Sha256: env.INFRACTORY_AGENT_AMD64_SHA256 } : {})
    ,...(env.INFRACTORY_PKI_HELPER_PATH ? { pkiHelperPath: env.INFRACTORY_PKI_HELPER_PATH } : {})
    ,encryptionKey,
    workerConcurrency: boundedInteger(env.WORKER_CONCURRENCY, 4, "WORKER_CONCURRENCY", 64),
    pulumiConcurrency: boundedInteger(env.PULUMI_CONCURRENCY, 2, "PULUMI_CONCURRENCY", 16)
  };
}
