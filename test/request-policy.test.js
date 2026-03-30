import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { createHash } from "node:crypto";
import { assert } from "chai";
import {
  createRequestSigningHeadersSignerFromConfig,
  RequestSigningHeadersSigner,
} from "../src/retriever/request-signing.js";
import { Session } from "../src/retriever/session.js";
import {
  mergeRequestPolicies,
  normalizeRequestPolicy,
  resolveRequestPolicyHeaders,
} from "../src/retriever/request-policy.js";

const testPem =
  "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFyanLfQsoXbxClFLDeTcepr5MpqIv6ZzvO7Mqkj5mlL\n-----END PRIVATE KEY-----";

describe("request policy", () => {
  it("normalizes customer headers from an object", () => {
    assert.deepEqual(
      normalizeRequestPolicy({
        customerHeaders: {
          Authorization: "Bearer token",
          Cookie: "a=b",
        },
        enableRequestSigning: true,
      }),
      {
        customerHeaders: [
          { name: "Authorization", value: "Bearer token" },
          { name: "Cookie", value: "a=b" },
        ],
        enableRequestSigning: true,
        sendCustomerHeadersOverHttp: false,
      }
    );
  });

  it("normalizes customer headers from an array of header lines", () => {
    assert.deepEqual(
      normalizeRequestPolicy({
        headers: ["Authorization: Bearer token", "Cookie: a=b"],
      }),
      {
        customerHeaders: [
          { name: "Authorization", value: "Bearer token" },
          { name: "Cookie", value: "a=b" },
        ],
        enableRequestSigning: false,
        sendCustomerHeadersOverHttp: false,
      }
    );
  });

  it("keeps customer headers off HTTP by default", () => {
    const requestPolicy = normalizeRequestPolicy({
      customerHeaders: {
        Authorization: "Bearer token",
      },
    });
    const result = resolveRequestPolicyHeaders({
      requestUrl: new URL("http://example.com/"),
      requestPolicy,
    });

    assert.deepEqual(result.customerHeaders, {});
  });

  it("sends customer headers over HTTP when explicitly enabled", () => {
    const requestPolicy = normalizeRequestPolicy({
      customerHeaders: {
        Authorization: "Bearer token",
      },
      sendCustomerHeadersOverHttp: true,
    });
    const result = resolveRequestPolicyHeaders({
      requestUrl: new URL("http://example.com/"),
      requestPolicy,
    });

    assert.deepEqual(result.customerHeaders, {
      Authorization: "Bearer token",
    });
  });

  it("accepts the legacy sendHeadersOverHttp flag", () => {
    assert.isTrue(
      normalizeRequestPolicy({
        sendHeadersOverHttp: true,
      })?.sendCustomerHeadersOverHttp
    );
  });

  it("applies customer headers on HTTPS", () => {
    const requestPolicy = normalizeRequestPolicy({
      customerHeaders: {
        Authorization: "Bearer token",
      },
    });
    const result = resolveRequestPolicyHeaders({
      requestUrl: new URL("https://example.com/"),
      requestPolicy,
    });

    assert.deepEqual(result.customerHeaders, {
      Authorization: "Bearer token",
    });
  });

  it("filters managed header names from customer headers", () => {
    const requestPolicy = normalizeRequestPolicy({
      customerHeaders: {
        Signature: "nope",
        Authorization: "Bearer token",
      },
    });
    const result = resolveRequestPolicyHeaders({
      requestUrl: new URL("https://example.com/"),
      requestPolicy,
    });

    assert.deepEqual(result.customerHeaders, {
      Authorization: "Bearer token",
    });
  });

  it("rejects customer header names with control characters", () => {
    assert.throws(
      () =>
        normalizeRequestPolicy({
          customerHeaders: {
            "X-Bad\r\nInjected": "value",
          },
        }),
      /Invalid customer header name/
    );
  });

  it("rejects customer header values with control characters", () => {
    assert.throws(
      () =>
        normalizeRequestPolicy({
          customerHeaders: {
            "X-Test": "value\r\nInjected: yes",
          },
        }),
      /Invalid customer header value/
    );
  });

  it("rejects non-object customer header collections", () => {
    assert.throws(
      () =>
        normalizeRequestPolicy({
          customerHeaders: "X-Test: value",
        }),
      /Invalid customer header collection/
    );
  });

  it("does not allow customer headers to pollute object prototypes", () => {
    const requestPolicy = normalizeRequestPolicy({
      customerHeaders: JSON.parse('{"__proto__":"value","X-Test":"ok"}'),
    });
    const result = resolveRequestPolicyHeaders({
      requestUrl: new URL("https://example.com/"),
      requestPolicy,
    });

    assert.equal(Object.getPrototypeOf(result.customerHeaders), null);
    assert.equal(result.customerHeaders["X-Test"], "ok");
    assert.equal(result.customerHeaders["__proto__"], "value");
  });

  it("merges configured and per-scan request policies", () => {
    assert.deepEqual(
      mergeRequestPolicies(
        {
          enableRequestSigning: true,
          customerHeaders: {
            Authorization: "Bearer configured",
          },
        },
        {
          customerHeaders: ["Accept: text/plain"],
          sendCustomerHeadersOverHttp: true,
        }
      ),
      {
        enableRequestSigning: true,
        sendCustomerHeadersOverHttp: true,
        customerHeaders: [
          { name: "Authorization", value: "Bearer configured" },
          { name: "Accept", value: "text/plain" },
        ],
      }
    );
  });

  it("generates managed request-signing headers for HTTP and HTTPS requests", () => {
    const signer = new RequestSigningHeadersSigner(testPem, {
      now: () => 1700000000,
    });
    const requestPolicy = normalizeRequestPolicy({
      enableRequestSigning: true,
    });

    const httpHeaders = resolveRequestPolicyHeaders({
      requestUrl: new URL("http://example.com/"),
      requestPolicy,
      requestSigner: signer,
      existingHeaders: {
        Accept: "text/html",
      },
    }).managedHeaders;
    const httpsHeaders = resolveRequestPolicyHeaders({
      requestUrl: new URL("https://example.com/"),
      requestPolicy,
      requestSigner: signer,
      existingHeaders: {
        Accept: "text/html",
      },
    }).managedHeaders;

    assert.property(httpHeaders, "Signature");
    assert.property(httpsHeaders, "Signature");
    assert.equal(httpHeaders.Accept, "text/html");
    assert.equal(httpsHeaders.Accept, "text/html");
  });

  it("signs the request body when present", () => {
    const signer = new RequestSigningHeadersSigner(testPem, {
      now: () => 1700000000,
      signatureAgent: "https://example.com/.well-known/signing",
    });

    const headers = signer.buildSignatureHeaders(
      "post",
      "https://example.com/api",
      {
        Accept: "text/plain",
        "User-Agent": "Custom/1.0",
      },
      "hello"
    );

    assert.equal(headers.Accept, "text/plain");
    assert.equal(headers["User-Agent"], "Custom/1.0");
    assert.equal(
      headers["Signature-Agent"],
      '"https://example.com/.well-known/http-message-signatures-directory"'
    );
    assert.equal(
      headers["Content-Digest"],
      `sha-256=:${createHash("sha256").update("hello").digest("base64")}:`
    );
    assert.include(headers["Signature-Input"], '"@method"');
    assert.include(headers["Signature-Input"], '"@target-uri"');
    assert.include(headers["Signature-Input"], '"accept"');
    assert.include(headers["Signature-Input"], '"user-agent"');
    assert.include(headers["Signature-Input"], '"content-digest"');
    assert.match(headers.Signature, /^sig2=:/);
  });

  it("lets customer headers override request defaults when signing", () => {
    const signer = new RequestSigningHeadersSigner(testPem, {
      now: () => 1700000000,
    });
    const requestPolicy = normalizeRequestPolicy({
      customerHeaders: {
        Accept: "text/plain",
      },
      enableRequestSigning: true,
    });

    const { managedHeaders } = resolveRequestPolicyHeaders({
      requestUrl: new URL("https://example.com/"),
      requestPolicy,
      requestSigner: signer,
      existingHeaders: {
        Accept: "text/html",
      },
    });

    assert.equal(managedHeaders.Accept, "text/plain");
  });

  it("creates a request signer from a configured PEM path", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "request-signing-"));
    const privateKeyPath = path.join(dir, "request-signing-key.pem");
    writeFileSync(privateKeyPath, testPem);

    const signer = createRequestSigningHeadersSignerFromConfig({
      privateKeyPath,
    });

    assert.instanceOf(signer, RequestSigningHeadersSigner);
  });

  it("throws a readable error when the configured PEM path cannot be read", () => {
    assert.throws(
      () =>
        createRequestSigningHeadersSignerFromConfig({
          privateKeyPath: "/no/such/request-signing.pem",
        }),
      /Unable to read request signing private key from \/no\/such\/request-signing\.pem/
    );
  });

  it("fails closed when request signing is enabled without a configured key path", () => {
    assert.throws(
      () =>
        new Session(new URL("https://example.com/"), {
          requestPolicy: {
            enableRequestSigning: true,
          },
        }),
      /request signer was not provided/
    );
  });
});
