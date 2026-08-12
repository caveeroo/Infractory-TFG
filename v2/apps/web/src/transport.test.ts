import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createAwsConnection, createWorkload, createWorkloadVersion,
  startDestroy, validateAwsConnection
} from "./transport";
import type { WorkloadManifest } from "@infractory/contracts";

const uuid = "11111111-1111-4111-8111-111111111111";
const environmentId = "22222222-2222-4222-8222-222222222222";
const now = "2026-08-12T08:00:00.000Z";

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));
}

beforeEach(() => vi.mocked(fetch).mockReset());

describe("real API transport", () => {
  it("creates a workload and publishes the complete runtime manifest", async () => {
    vi.mocked(fetch)
      .mockImplementationOnce(() => json({ id: uuid, name: "Redirector", description: "Public edge", createdAt: now }, 201))
      .mockImplementationOnce(() => json({ id: environmentId, workloadId: uuid, version: "1.0.0", digest: "a".repeat(64), composeYaml: "services:\n  app:\n    image: example/app@sha256:" + "b".repeat(64), manifest: { schemaVersion: 1, inputsSchema: {}, secretFiles: [], endpoints: [], placement: { requiredRoles: [] }, probes: [] }, createdAt: now }, 201));
    const manifest: WorkloadManifest = {
      schemaVersion: 1,
      inputsSchema: { type: "object", properties: { api_token: { type: "string" } }, required: ["api_token"], additionalProperties: false },
      secretFiles: [{ input: "api_token", target: "secrets/api_token" }],
      endpoints: [{ name: "HTTPS", protocol: "tcp", port: 443, scope: "public" }],
      placement: { requiredRoles: ["redirector"] },
      probes: [{ kind: "http", target: "http://app:8080/health", timeoutSeconds: 30 }]
    };
    const workload = await createWorkload("Redirector", "Public edge");
    await createWorkloadVersion(workload.id, "1.0.0", "services:\n  app:\n    image: example/app@sha256:" + "b".repeat(64), manifest);

    expect(fetch).toHaveBeenNthCalledWith(1, "/api/v1/workloads", expect.objectContaining({ method: "POST" }));
    const versionInit = vi.mocked(fetch).mock.calls[1]?.[1];
    expect(JSON.parse(String(versionInit?.body))).toMatchObject({ version: "1.0.0", manifest });
  });

  it("validates credentials before saving only account metadata", async () => {
    const identity = { accountId: "071234567890", partition: "aws", principalArn: "arn:aws:iam::071234567890:role/Infractory", validatedAt: now };
    vi.mocked(fetch)
      .mockImplementationOnce(() => json(identity))
      .mockImplementationOnce(() => json({ id: uuid, name: "production", ...identity, createdAt: now }, 201));

    expect(await validateAwsConnection()).toEqual(identity);
    await createAwsConnection("production");

    expect(JSON.parse(String(vi.mocked(fetch).mock.calls[1]?.[1]?.body))).toEqual({ name: "production" });
  });

  it("starts destroy with confirmation and a unique idempotency key", async () => {
    vi.mocked(fetch).mockImplementationOnce(() => json({
      id: uuid, environmentId, kind: "destroy", state: "queued", revision: 4,
      idempotencyKey: "request-key", retryOfOperationId: null, planOperationId: null,
      result: null, createdAt: now, startedAt: null, finishedAt: null, steps: []
    }, 202));

    await startDestroy(environmentId, "Aurora", true);
    const [, init] = vi.mocked(fetch).mock.calls[0]!;
    expect(init?.headers).toEqual(expect.objectContaining({ "Idempotency-Key": expect.any(String) }));
    expect(JSON.parse(String(init?.body))).toEqual({ confirmName: "Aurora", acknowledgeResidualRisk: true });
  });
});
