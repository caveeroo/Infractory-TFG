import { describe, expect, it } from "vitest";
import { sanitizeProviderValue } from "../src/adapters/pulumi-infrastructure.js";

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
});
