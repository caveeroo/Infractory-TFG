import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false
  })
});

vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
  id: "00000000-0000-4000-8000-000000000001",
  name: "Aurora",
  lifecycle: "active",
  health: "healthy",
  desiredRevision: 7,
  appliedRevision: 7,
  expiresAt: null,
  createdAt: "2026-08-12T08:00:00.000Z",
  updatedAt: "2026-08-12T08:41:00.000Z",
  etag: "revision-7",
  spec: {
    schemaVersion: 1,
    name: "Aurora",
    region: "eu-west-1",
    network: { cidr: "10.42.0.0/24", lighthouseNodeKeys: ["northstar"] },
    nodes: [{ key: "northstar", name: "northstar", roles: ["lighthouse"], source: { kind: "aws", instanceType: "t3.small", architecture: "amd64", publicEndpoint: true } }],
    deployments: []
  }
}), { status: 200, headers: { "content-type": "application/json" } })));
