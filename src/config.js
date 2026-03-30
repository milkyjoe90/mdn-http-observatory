import convict from "convict";
import { existsSync } from "node:fs";
import path from "node:path";

const SCHEMA = {
  retriever: {
    retrieverUserAgent: {
      doc: "The user agent to use for retriever requests.",
      format: "String",
      default:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0 Observatory/129.0",
      env: "RETRIEVER_USER_AGENT",
    },
    corsOrigin: {
      doc: "The CORS origin to use for CORS origin retriever requests.",
      format: "String",
      default: "https://http-observatory.security.mozilla.org",
      env: "CORS_ORIGIN",
    },
    abortTimeout: {
      doc: "The overall timeout for a request, in ms",
      format: "Number",
      default: 10000,
      env: "ABORT_TIMEOUT",
    },
    clientTimeout: {
      doc: "The timeout once the request has been sent, in ms",
      format: "Number",
      default: 9000,
      env: "CLIENT_TIMEOUT",
    },
    requestPolicy: {
      enableRequestSigning: {
        doc: "Enable request signing for retriever requests.",
        format: "Boolean",
        default: false,
      },
      sendCustomerHeadersOverHttp: {
        doc: "Also send configured customer headers over HTTP.",
        format: "Boolean",
        default: false,
      },
      customerHeaders: {
        doc: "Configured customer headers to send with retriever requests.",
        format: Object,
        default: {},
      },
    },
    requestSigning: {
      privateKeyPath: {
        doc: "Path to the PKCS#8 PEM private key used for request signing.",
        format: "String",
        default: "",
      },
      signatureAgent: {
        doc: "Signature-Agent directory URL for signed requests.",
        format: "String",
        default: "",
      },
      acceptHeader: {
        doc: "Default Accept header for signed requests.",
        format: "String",
        default: "",
      },
      userAgent: {
        doc: "Default User-Agent header for signed requests.",
        format: "String",
        default: "",
      },
      keyId: {
        doc: "Explicit key id to use for signed requests.",
        format: "String",
        default: "",
      },
      tag: {
        doc: "Tag to use for signed requests.",
        format: "String",
        default: "",
      },
    },
  },
  database: {
    database: {
      doc: "The name of the database to use",
      format: "String",
      default: "",
      env: "PGDATABASE",
    },
    host: {
      doc: "The database server hostname",
      format: "String",
      default: "localhost",
      env: "PGHOST",
    },
    user: {
      doc: "Database username",
      format: "String",
      default: "",
      env: "PGUSER",
    },
    pass: {
      doc: "Database password",
      format: "String",
      default: "",
      sensitive: true,
      env: "PGPASSWORD",
    },
    port: {
      doc: "The port of the database service",
      format: "port",
      default: 5432,
      env: "PGPORT",
    },
    sslmode: {
      doc: "Database SSL mode",
      format: "Boolean",
      default: false,
      env: "PGSSLMODE",
    },
  },
  api: {
    cooldown: {
      doc: "Cached result time for API V2, in Seconds. Defaults to 1 minute",
      format: "nat",
      default: 60,
      env: "HTTPOBS_API_COOLDOWN",
    },
    cacheTimeForGet: {
      doc: "Maximum scan age a GET request returns before initiating a new scan, in seconds. Defaults to 24 hours.",
      format: "nat",
      default: 86400,
      env: "HTTPOBS_API_GET_CACHE",
    },
    port: {
      doc: "The port to bind to",
      format: "Number",
      default: 8080,
      env: "HTTPOBS_API_PORT",
    },
    enableLogging: {
      doc: "Enable server logging",
      format: "Boolean",
      default: true,
      env: "HTTPOBS_ENABLE_LOGGING",
    },
  },
  sentry: {
    dsn: {
      doc: "The Sentry data source name (DSN) to use for error reporting.",
      format: "String",
      default: "",
      env: "SENTRY_DSN",
    },
  },
  tests: {
    hostForPortAndPathChecks: {
      doc: "Host to use for custom port and path checks",
      format: "String",
      default: "",
      env: "HTTPOBS_TESTS_HOST_FOR_PORT_AND_PATH_CHECKS",
    },
  },
};

/**
 *
 * @param {string | undefined} configFile
 * @returns
 */
export function load(configFile) {
  const configuration = convict(SCHEMA);
  try {
    if (configFile) {
      configuration.loadFile(configFile);
    }
    configuration.validate({ allowed: "strict" });
    const properties = configuration.getProperties();
    const privateKeyPath = properties.retriever.requestSigning.privateKeyPath;
    if (configFile && privateKeyPath && !path.isAbsolute(privateKeyPath)) {
      properties.retriever.requestSigning.privateKeyPath = path.resolve(
        path.dirname(configFile),
        privateKeyPath
      );
    }
    return properties;
  } catch (e) {
    throw new Error(`error reading config: ${e}`);
  }
}

export const DEFAULT_CONFIG_FILE = "config/config.json";
export const CONFIG = load(
  process.env["CONFIG_FILE"] ||
    (existsSync(DEFAULT_CONFIG_FILE) ? DEFAULT_CONFIG_FILE : undefined)
);
