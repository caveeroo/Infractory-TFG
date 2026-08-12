import { describe, expect, it } from "vitest";
import { instanceResourceOptions, planChangeFromEvent, sanitizeProviderValue } from "../src/adapters/pulumi-infrastructure.js";
import type { EngineEvent } from "@pulumi/pulumi/automation/index.js";

describe("provider observation sanitization", () => {
  it("redacts secret-shaped fields recursively while retaining diagnostics", () => {
    const observed = sanitizeProviderValue({
      id: "i-123",
      nested: {
        userDataBase64: "contains-enrollment-token",
        privateKey: "private-material",
        publicIp: "203.0.113.10"
      },
      values: [{ password: "plaintext" }, { status: "running" }]
    });

    expect(observed).toEqual({
      id: "i-123",
      nested: { userDataBase64: "[REDACTED]", privateKey: "[REDACTED]", publicIp: "203.0.113.10" },
      values: [{ password: "[REDACTED]" }, { status: "running" }]
    });
    expect(JSON.stringify(observed)).not.toContain("enrollment-token");
    expect(JSON.stringify(observed)).not.toContain("plaintext");
  });

  it("redacts Pulumi secret envelopes without inspecting ciphertext", () => {
    expect(sanitizeProviderValue({
      "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
      ciphertext: "opaque-but-sensitive"
    })).toBe("[REDACTED]");
  });

  it("retains bootstrap data for stable instances and refreshes it on replacement", () => {
    expect(instanceResourceOptions(false)).toMatchObject({ ignoreChanges: ["userDataBase64"], replaceOnChanges: ["instanceType"] });
    expect(instanceResourceOptions(true)).toMatchObject({ replaceOnChanges: ["instanceType", "userDataBase64"] });
    expect(instanceResourceOptions(true)).not.toHaveProperty("ignoreChanges");
  });

  it("preserves per-instance replacement identity in reviewed plans", () => {
    const event = { resourcePreEvent: { metadata: { op: "create-replacement", urn: "urn:pulumi:environment::project::aws:ec2/instance:Instance::node-relay", type: "aws:ec2/instance:Instance" } } } as EngineEvent;
    expect(planChangeFromEvent(event)).toMatchObject({ action: "replace", resourceType: "aws:ec2/instance:Instance", resourceKey: "node-relay", destructive: true });
  });
});
