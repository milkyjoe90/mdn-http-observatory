import { describe, it } from "node:test";
import { assert } from "chai";
import {
  buildCliRequestPolicy,
  formatScanResult,
  parseHeadersOption,
} from "../src/scan.js";

describe("parseHeadersOption", () => {
  it("converts a JSON object to header strings", () => {
    const result = parseHeadersOption(
      '{"X-Foo": "bar", "Authorization": "Bearer tok"}'
    );
    assert.deepEqual(result, ["X-Foo: bar", "Authorization: Bearer tok"]);
  });

  it("handles an empty object", () => {
    assert.deepEqual(parseHeadersOption("{}"), []);
  });

  it("throws on invalid JSON", () => {
    assert.throws(() => parseHeadersOption("not-json"), /Invalid JSON/);
  });

  it("handles a single header", () => {
    assert.deepEqual(parseHeadersOption('{"X-Custom": "value"}'), [
      "X-Custom: value",
    ]);
  });

  it("rejects header names with control characters", () => {
    assert.throws(
      () => parseHeadersOption('{"X-Bad\\r\\nInjected": "value"}'),
      /Invalid customer header name/
    );
  });

  it("rejects header values with control characters", () => {
    assert.throws(
      () => parseHeadersOption('{"X-Test": "value\\r\\nInjected: yes"}'),
      /Invalid customer header value/
    );
  });

  it("rejects non-object header collections", () => {
    assert.throws(
      () => parseHeadersOption('"X-Test: value"'),
      /Invalid customer header collection/
    );
  });

  it("rejects boolean header collections", () => {
    assert.throws(
      () => parseHeadersOption("false"),
      /Invalid customer header collection/
    );
  });
});

describe("formatScanResult", () => {
  it("formats scan results without scoreDescription", () => {
    const formatted = formatScanResult({
      scan: {
        grade: "A",
      },
      tests: {
        Example: {
          pass: true,
          result: "ok",
          scoreDescription: "hidden",
        },
      },
    });

    assert.deepEqual(formatted, {
      scan: {
        grade: "A",
      },
      tests: {
        Example: {
          pass: true,
          result: "ok",
        },
      },
    });
  });
});

describe("buildCliRequestPolicy", () => {
  it("returns undefined when no request-policy options are set", () => {
    assert.isUndefined(buildCliRequestPolicy());
  });

  it("builds a request-policy fragment from CLI options", () => {
    assert.deepEqual(
      buildCliRequestPolicy({
        headers: '{"Authorization":"Bearer tok"}',
        sendHeadersOverHttp: true,
      }),
      {
        customerHeaders: ["Authorization: Bearer tok"],
        sendCustomerHeadersOverHttp: true,
      }
    );
  });
});
