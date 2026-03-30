import { readFileSync } from "node:fs";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";

const DEFAULT_SIGNATURE_AGENT =
  "https://request-signer.invalid/.well-known/http-message-signatures-directory";
const DEFAULT_ACCEPT_HEADER = "application/json";
const DEFAULT_USER_AGENT =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const DEFAULT_EXPIRY_TTL_SECONDS = 120;
const DEFAULT_SIGNATURE_TAG = "request-signing";

function normalizeSignatureAgent(url) {
  if (!url) {
    return DEFAULT_SIGNATURE_AGENT;
  }

  try {
    const parsed = new URL(url);
    return `${parsed.origin}/.well-known/http-message-signatures-directory`;
  } catch {
    return DEFAULT_SIGNATURE_AGENT;
  }
}

function toBase64Url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function getAuthority(uri) {
  if (!uri) {
    return "";
  }

  const defaultPort =
    (uri.protocol === "https:" && uri.port === "443") ||
    (uri.protocol === "http:" && uri.port === "80") ||
    uri.port === "";
  return defaultPort ? uri.hostname : `${uri.hostname}:${uri.port}`;
}

function toBodyBytes(data) {
  if (!data) {
    return null;
  }

  if (Buffer.isBuffer(data)) {
    return data;
  }

  if (typeof data === "string") {
    return Buffer.from(data);
  }

  if (data instanceof Uint8Array) {
    return Buffer.from(data);
  }

  return null;
}

export class RequestSigningHeadersSigner {
  /**
   * @param {string} pkcs8Pem
   * @param {{ signatureAgent?: string, acceptHeader?: string, userAgent?: string, tag?: string, kid?: string, now?: () => number }} [options]
   */
  constructor(pkcs8Pem, options = {}) {
    if (!pkcs8Pem || pkcs8Pem.trim() === "") {
      throw new Error("Request signing private key is empty.");
    }

    this.privateKey = createPrivateKey(pkcs8Pem);
    this.publicKey = createPublicKey(this.privateKey);
    const exported = this.publicKey.export({ format: "jwk" });
    this.kid =
      options.kid ||
      toBase64Url(
        createHash("sha256")
          .update(
            JSON.stringify({
              crv: exported.crv,
              kty: exported.kty,
              x: exported.x,
            })
          )
          .digest()
      );
    this.signatureAgent = normalizeSignatureAgent(options.signatureAgent);
    this.acceptHeader =
      options.acceptHeader && options.acceptHeader.trim() !== ""
        ? options.acceptHeader
        : DEFAULT_ACCEPT_HEADER;
    this.userAgent =
      options.userAgent && options.userAgent.trim() !== ""
        ? options.userAgent
        : DEFAULT_USER_AGENT;
    this.tag =
      options.tag && options.tag.trim() !== ""
        ? options.tag
        : DEFAULT_SIGNATURE_TAG;
    this.now = options.now || (() => Math.floor(Date.now() / 1000));
  }

  /**
   * @param {string} method
   * @param {string} url
   * @param {Record<string, string>} existingHeaders
   * @param {unknown} data
   * @returns {Record<string, string>}
   */
  buildSignatureHeaders(method, url, existingHeaders = {}, data = null) {
    const normalizedMethod = method.toUpperCase();
    const lowerCaseHeaders = Object.entries(existingHeaders).reduce(
      (acc, [key, value]) => {
        acc[key.toLowerCase()] = value;
        return acc;
      },
      Object.create(null)
    );
    const userAgent = lowerCaseHeaders["user-agent"] || this.userAgent;
    const accept = lowerCaseHeaders.accept || this.acceptHeader;

    const bodyBytes = toBodyBytes(data);
    let contentDigestHeader = null;
    if (bodyBytes && bodyBytes.length > 0) {
      const digest = createHash("sha256").update(bodyBytes).digest("base64");
      contentDigestHeader = `sha-256=:${digest}:`;
    }

    const requestUrl = new URL(url);
    const created = this.now();
    const expires = created + DEFAULT_EXPIRY_TTL_SECONDS;
    const targetUri = `${requestUrl.origin}${requestUrl.pathname}${requestUrl.search}`;
    const coveredComponents = [
      '"@method"',
      '"@authority"',
      '"@target-uri"',
      '"accept"',
      '"user-agent"',
      '"signature-agent"',
    ];
    const signatureBaseLines = [
      `"@method": ${normalizedMethod}`,
      `"@authority": ${getAuthority(requestUrl).toLowerCase()}`,
      `"@target-uri": ${targetUri}`,
      `"accept": ${accept}`,
      `"user-agent": ${userAgent}`,
      `"signature-agent": "${this.signatureAgent}"`,
    ];

    if (contentDigestHeader) {
      coveredComponents.push('"content-digest"');
      signatureBaseLines.push(`"content-digest": ${contentDigestHeader}`);
    }

    signatureBaseLines.push(
      `"@signature-params": (${coveredComponents.join(
        " "
      )});created=${created};expires=${expires};alg="ed25519";keyid="${this.kid}";tag="${this.tag}"`
    );

    const signature = sign(
      null,
      Buffer.from(signatureBaseLines.join("\n")),
      this.privateKey
    ).toString("base64");

    const signatureInput = `sig2=(${coveredComponents.join(
      " "
    )});created=${created};expires=${expires};alg="ed25519";keyid="${this.kid}";tag="${this.tag}"`;

    const headers = {
      "User-Agent": userAgent,
      Accept: accept,
      "Signature-Agent": `"${this.signatureAgent}"`,
      "Signature-Input": signatureInput,
      Signature: `sig2=:${signature}:`,
    };

    if (contentDigestHeader) {
      headers["Content-Digest"] = contentDigestHeader;
    }

    return headers;
  }
}

export function createRequestSigningHeadersSignerFromConfig(config = {}) {
  const privateKeyPath = config.privateKeyPath?.trim();
  if (!privateKeyPath) {
    return null;
  }

  let pem;
  try {
    pem = readFileSync(privateKeyPath, "utf8");
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Unable to read request signing private key from ${privateKeyPath}: ${reason}`
    );
  }

  return new RequestSigningHeadersSigner(pem, {
    signatureAgent: config.signatureAgent,
    acceptHeader: config.acceptHeader,
    userAgent: config.userAgent,
    kid: config.keyId,
    tag: config.tag,
  });
}
