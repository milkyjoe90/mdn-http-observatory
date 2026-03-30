#!/usr/bin/env node

import { Command } from "commander";
import { scan } from "./scanner/index.js";
import { Site } from "./site.js";
import { normalizeHeaderEntries } from "./retriever/request-policy.js";

/**
 * @param {string} json
 * @returns {string[]}
 */
export function parseHeadersOption(json) {
  let parsed;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("Invalid JSON for --headers");
  }
  return normalizeHeaderEntries(parsed).map(
    ({ name, value }) => `${name}: ${value}`
  );
}

export function formatScanResult(result) {
  return {
    scan: result.scan,
    tests: Object.fromEntries(
      Object.entries(result.tests).map(([key, test]) => {
        const { scoreDescription, ...rest } = test;
        return [key, rest];
      })
    ),
  };
}

/**
 * @param {{ headers?: string, sendHeadersOverHttp?: boolean }} options
 * @returns {import("./types.js").RequestPolicyInput | undefined}
 */
export function buildCliRequestPolicy({ headers, sendHeadersOverHttp } = {}) {
  if (!headers && !sendHeadersOverHttp) {
    return undefined;
  }

  return {
    ...(headers ? { customerHeaders: parseHeadersOption(headers) } : {}),
    ...(sendHeadersOverHttp ? { sendCustomerHeadersOverHttp: true } : {}),
  };
}

const NAME = "mdn-http-observatory-scan";
const program = new Command();

program
  .name(NAME)
  .description("CLI for the MDN HTTP Observatory scan functionality")
  .version("1.0.0")
  .argument("<hostname>", "hostname to scan")
  .option(
    "--headers <json>",
    "Send custom request headers (JSON-formatted, HTTPS only by default)"
  )
  .option(
    "--send-headers-over-http",
    "Also send custom headers over unencrypted HTTP"
  )
  .action(async (siteString, options) => {
    try {
      /** @type {import("./types.js").ScanOptions} */
      const scanOptions = {};
      const requestPolicy = buildCliRequestPolicy({
        headers: options.headers,
        sendHeadersOverHttp: options.sendHeadersOverHttp,
      });
      if (requestPolicy) {
        scanOptions.requestPolicy = requestPolicy;
      }
      const site = Site.fromSiteString(siteString);
      const result = await scan(site, scanOptions);
      const ret = formatScanResult(result);
      console.log(JSON.stringify(ret, null, 2));
    } catch (e) {
      if (e instanceof Error) {
        console.log(JSON.stringify({ error: e.message }));
        process.exit(1);
      }
    }
  });

if (import.meta.url === `file://${process.argv[1]}`) {
  program.parse();
}
