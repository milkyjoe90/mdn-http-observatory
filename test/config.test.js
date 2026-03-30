import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { assert } from "chai";
import { load } from "../src/config.js";

describe("config", () => {
  it("exposes the retriever request-policy and request-signing defaults", () => {
    const config = load();

    assert.deepEqual(config.retriever.requestPolicy, {
      enableRequestSigning: false,
      sendCustomerHeadersOverHttp: false,
      customerHeaders: {},
    });
    assert.deepEqual(config.retriever.requestSigning, {
      privateKeyPath: "",
      signatureAgent: "",
      acceptHeader: "",
      userAgent: "",
      keyId: "",
      tag: "",
    });
  });

  it("honors env overrides for top-level config values", () => {
    const originalUserAgent = process.env.RETRIEVER_USER_AGENT;
    process.env.RETRIEVER_USER_AGENT = "Bot/1.0";

    try {
      const config = load();
      assert.equal(config.retriever.retrieverUserAgent, "Bot/1.0");
    } finally {
      if (originalUserAgent === undefined) {
        delete process.env.RETRIEVER_USER_AGENT;
      } else {
        process.env.RETRIEVER_USER_AGENT = originalUserAgent;
      }
    }
  });

  it("resolves request signing privateKeyPath relative to the config file", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "httpobs-config-"));
    const configPath = path.join(dir, "config.json");
    const keyPath = path.join(dir, "keys", "request-signing.pem");

    writeFileSync(
      configPath,
      JSON.stringify({
        retriever: {
          requestSigning: {
            privateKeyPath: "./keys/request-signing.pem",
          },
        },
      })
    );

    const config = load(configPath);

    assert.equal(config.retriever.requestSigning.privateKeyPath, keyPath);
  });
});
