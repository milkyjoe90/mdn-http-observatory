const MANAGED_HEADER_NAMES = new Set(
  [
    "signature",
    "signature-agent",
    "signature-input",
    "content-digest",
  ].map((name) => name.toLowerCase())
);

const VALID_HEADER_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

function hasControlCharacters(value) {
  return /[\0-\x1F\x7F]/.test(value);
}

function normalizeHeaderName(name) {
  const normalizedName = String(name).trim();
  if (!VALID_HEADER_NAME_PATTERN.test(normalizedName)) {
    throw new Error("Invalid customer header name.");
  }
  return normalizedName;
}

function normalizeHeaderValue(value) {
  const normalizedValue = String(value ?? "");
  if (hasControlCharacters(normalizedValue)) {
    throw new Error("Invalid customer header value.");
  }
  return normalizedValue.trim();
}

export function normalizeHeaderEntries(headers) {
  if (headers == null) {
    return [];
  }

  if (Array.isArray(headers)) {
    return headers
      .map((entry) => {
        if (typeof entry === "string") {
          const separator = entry.indexOf(":");
          if (separator <= 0) {
            throw new Error("Invalid customer header entry.");
          }

          return {
            name: normalizeHeaderName(entry.slice(0, separator)),
            value: normalizeHeaderValue(entry.slice(separator + 1)),
          };
        }

        if (
          entry &&
          typeof entry === "object" &&
          "name" in entry &&
          "value" in entry
        ) {
          return {
            name: normalizeHeaderName(entry.name),
            value: normalizeHeaderValue(entry.value),
          };
        }

        throw new Error("Invalid customer header entry.");
      })
      .filter((entry) => entry.name !== "");
  }

  if (typeof headers !== "object") {
    throw new Error("Invalid customer header collection.");
  }

  return Object.entries(headers)
    .map(([name, value]) => ({
      name: normalizeHeaderName(name),
      value: normalizeHeaderValue(value),
    }))
    .filter((entry) => entry.name !== "");
}

function toHeaderObject(entries) {
  return entries.reduce((acc, entry) => {
    acc[entry.name] = entry.value;
    return acc;
  }, Object.create(null));
}

/**
 * @param {import("../types.js").RequestPolicyInput | undefined} requestPolicy
 * @returns {import("../types.js").NormalizedRequestPolicy | null}
 */
export function normalizeRequestPolicy(requestPolicy) {
  if (!requestPolicy) {
    return null;
  }

  const customerHeaders = normalizeHeaderEntries(
    requestPolicy.customerHeaders ?? requestPolicy.headers
  );

  const normalizedRequestPolicy = {
    enableRequestSigning: requestPolicy.enableRequestSigning === true,
    sendCustomerHeadersOverHttp:
      requestPolicy.sendCustomerHeadersOverHttp === true ||
      requestPolicy.sendHeadersOverHttp === true,
    customerHeaders,
  };

  if (
    !normalizedRequestPolicy.enableRequestSigning &&
    !normalizedRequestPolicy.sendCustomerHeadersOverHttp &&
    normalizedRequestPolicy.customerHeaders.length === 0
  ) {
    return null;
  }

  return normalizedRequestPolicy;
}

/**
 * @param {...(import("../types.js").RequestPolicyInput | import("../types.js").NormalizedRequestPolicy | null | undefined)} requestPolicies
 * @returns {import("../types.js").NormalizedRequestPolicy | null}
 */
export function mergeRequestPolicies(...requestPolicies) {
  const mergedRequestPolicy = {
    enableRequestSigning: false,
    sendCustomerHeadersOverHttp: false,
    customerHeaders: [],
  };

  for (const requestPolicy of requestPolicies) {
    const normalizedRequestPolicy = normalizeRequestPolicy(requestPolicy);
    if (!normalizedRequestPolicy) {
      continue;
    }

    mergedRequestPolicy.enableRequestSigning ||= 
      normalizedRequestPolicy.enableRequestSigning;
    mergedRequestPolicy.sendCustomerHeadersOverHttp ||=
      normalizedRequestPolicy.sendCustomerHeadersOverHttp;
    mergedRequestPolicy.customerHeaders.push(
      ...normalizedRequestPolicy.customerHeaders
    );
  }

  return normalizeRequestPolicy(mergedRequestPolicy);
}

/**
 * @param {{ requestUrl: URL, method?: string, existingHeaders?: Record<string, string>, data?: unknown, requestPolicy?: import("../types.js").NormalizedRequestPolicy | null, requestSigner?: import("./request-signing.js").RequestSigningHeadersSigner | null }} options
 * @returns {{ customerHeaders: Record<string, string>, managedHeaders: Record<string, string> }}
 */
export function resolveRequestPolicyHeaders({
  requestUrl,
  method = "get",
  existingHeaders = {},
  data = null,
  requestPolicy = null,
  requestSigner = null,
}) {
  if (!requestPolicy) {
    return {
      customerHeaders: {},
      managedHeaders: {},
    };
  }

  const allowCustomerHeaders =
    requestUrl.protocol === "https:" ||
    requestPolicy.sendCustomerHeadersOverHttp === true;
  const customerHeaders = allowCustomerHeaders
    ? toHeaderObject(
        requestPolicy.customerHeaders.filter(
          (entry) => !MANAGED_HEADER_NAMES.has(entry.name.toLowerCase())
        )
      )
    : Object.create(null);
  const headersForSigning = allowCustomerHeaders
    ? {
        ...existingHeaders,
        ...customerHeaders,
      }
    : Object.assign(Object.create(null), existingHeaders);

  const managedHeaders =
    requestPolicy.enableRequestSigning && requestSigner
      ? requestSigner.buildSignatureHeaders(
          method.toUpperCase(),
          requestUrl.href,
          headersForSigning,
          data
        )
      : {};

  return {
    customerHeaders,
    managedHeaders,
  };
}
