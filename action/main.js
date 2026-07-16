"use strict";

const { appendFileSync } = require("node:fs");

const { validateExchangeUrl } = require("../scripts/validate-exchange-url.js");
const {
  addMask,
  appendFileCommand,
  ensureProxyConfiguration,
  parseHttpsUrl,
  requestJson,
  requiredString,
} = require("./common.js");

const repositoryPermissions = new Set([
  "actions",
  "administration",
  "artifact_metadata",
  "attestations",
  "checks",
  "code_quality",
  "codespaces",
  "contents",
  "dependabot_secrets",
  "deployments",
  "discussions",
  "environments",
  "issues",
  "merge_queues",
  "metadata",
  "packages",
  "pages",
  "pull_requests",
  "repository_custom_properties",
  "repository_hooks",
  "repository_projects",
  "secret_scanning_alerts",
  "secrets",
  "security_events",
  "single_file",
  "statuses",
  "vulnerability_alerts",
  "workflows",
]);

function parsePermissions(input) {
  const permissions = Object.create(null);
  for (const line of input.split(/\r?\n/u)) {
    if (!line.trim()) continue;
    const match = /^\s*([a-z_]+)\s*:\s*(read|write|admin)\s*$/u.exec(line);
    if (!match) throw new Error("permissions must contain one name: level entry per line");
    const [, name, level] = match;
    if (!repositoryPermissions.has(name)) {
      throw new Error(`unknown repository permission: ${name}`);
    }
    if ((name === "workflows" && level !== "write") || (name !== "repository_projects" && level === "admin")) {
      throw new Error(`invalid level for repository permission: ${name}`);
    }
    if (Object.hasOwn(permissions, name)) {
      throw new Error(`duplicate repository permission: ${name}`);
    }
    permissions[name] = level;
  }
  if (!Object.keys(permissions).length) {
    throw new Error("permissions must not be empty");
  }
  return permissions;
}

async function run({
  env = process.env,
  fetchImpl = globalThis.fetch,
  appendFile = appendFileSync,
  write = process.stdout.write.bind(process.stdout),
  uuid,
} = {}) {
  const exchangeUrl = env["INPUT_EXCHANGE-URL"];
  const audience = env.INPUT_AUDIENCE;
  validateExchangeUrl(exchangeUrl, audience);
  const repository = env.INPUT_REPOSITORY;
  const permissionsInput = env.INPUT_PERMISSIONS;
  if (Boolean(repository) !== Boolean(permissionsInput)) {
    throw new Error("repository and permissions must be provided together");
  }
  if (
    repository &&
    !/^(?!\.{1,2}\/)(?![^/]+\/\.{1,2}$)[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository)
  ) {
    throw new Error("repository must be OWNER/REPO");
  }
  const permissions = permissionsInput && parsePermissions(permissionsInput);

  const oidcRequestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const oidcRequestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!oidcRequestUrl || !oidcRequestToken) {
    throw new Error("id-token: write is required to request a GitHub OIDC token");
  }

  ensureProxyConfiguration(env);
  const oidcUrl = parseHttpsUrl(oidcRequestUrl, "ACTIONS_ID_TOKEN_REQUEST_URL", true);
  oidcUrl.searchParams.set("audience", audience);

  const oidcResponse = await requestJson(
    fetchImpl,
    oidcUrl.toString(),
    { headers: { authorization: `bearer ${oidcRequestToken}` } },
    "OIDC token",
  );
  const oidcToken = requiredString(oidcResponse.value, "OIDC token");
  addMask(oidcToken, write);

  const exchangeResponse = await requestJson(
    fetchImpl,
    exchangeUrl,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${oidcToken}`,
        ...(repository && { "content-type": "application/json" }),
      },
      body: repository
        ? JSON.stringify({ repository, permissions })
        : "",
    },
    "token exchange",
  );
  const token = requiredString(exchangeResponse.token, "installation token");
  addMask(token, write);
  appendFileCommand(env.GITHUB_STATE, "token", token, appendFile, uuid);

  const expiresAt = requiredString(exchangeResponse.expires_at, "installation token expiration");
  appendFileCommand(env.GITHUB_STATE, "expiresAt", expiresAt, appendFile, uuid);
  const returnedRepository = requiredString(exchangeResponse.repository, "repository");
  if (repository && returnedRepository !== repository) {
    throw new Error("returned repository does not match the requested repository");
  }
  const ref = requiredString(exchangeResponse.ref, "ref");

  for (const [name, value] of [
    ["token", token],
    ["expires-at", expiresAt],
    ["repository", returnedRepository],
    ["ref", ref],
  ]) {
    appendFileCommand(env.GITHUB_OUTPUT, name, value, appendFile, uuid);
  }
}

if (require.main === module) {
  run().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { run };
