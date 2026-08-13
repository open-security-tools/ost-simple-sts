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

const branchRefPrefix = "refs/heads/";
const maxBranchRefLength = 255;

function validBranchRef(value) {
  if (!value.startsWith(branchRefPrefix) || value.length > maxBranchRefLength) {
    return false;
  }

  const branch = value.slice(branchRefPrefix.length);
  return (
    /^[A-Za-z0-9._/-]+$/u.test(branch) &&
    !branch.startsWith("-") &&
    !branch.endsWith(".") &&
    !branch.includes("..") &&
    branch.split("/").every((part) => part && !part.startsWith(".") && !part.endsWith(".lock"))
  );
}

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

function parseRepositories(input) {
  const repositories = input
    .split(/\r?\n/u)
    .map((repository) => repository.trim())
    .filter(Boolean);
  if (repositories.length < 2) {
    throw new Error("repositories must contain at least two OWNER/REPO entries");
  }
  const seen = new Set();
  for (const repository of repositories) {
    if (!/^(?!\.{1,2}\/)(?![^/]+\/\.{1,2}$)[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository)) {
      throw new Error("repositories must contain one OWNER/REPO entry per line");
    }
    const normalized = repository.toLowerCase();
    if (seen.has(normalized)) {
      throw new Error(`duplicate repository: ${repository}`);
    }
    seen.add(normalized);
  }
  return repositories;
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
  const repositoriesInput = env.INPUT_REPOSITORIES;
  const permissionsInput = env.INPUT_PERMISSIONS;
  if (repository && repositoriesInput) {
    throw new Error("repository and repositories are mutually exclusive");
  }
  if (Boolean(repository || repositoriesInput) !== Boolean(permissionsInput)) {
    throw new Error("repository or repositories and permissions must be provided together");
  }
  if (
    repository &&
    !/^(?!\.{1,2}\/)(?![^/]+\/\.{1,2}$)[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository)
  ) {
    throw new Error("repository must be OWNER/REPO");
  }
  const repositories = repositoriesInput && parseRepositories(repositoriesInput);
  const permissions = permissionsInput && parsePermissions(permissionsInput);
  const delivery = env.INPUT_DELIVERY || "token";
  if (delivery === "github-proxy" && env.RUNNER_DEBUG === "1") {
    throw new Error(
      "github-proxy delivery is disabled when RUNNER_DEBUG=1 because GitHub Actions debug logging may expose the proxy capability; disable runner debug logging and retry",
    );
  }
  const branch = env.INPUT_BRANCH || "";
  const expectedHead = env["INPUT_EXPECTED-HEAD"] || "";
  let proxyDelivery;
  if (delivery === "github-proxy") {
    if (!repository || repositoriesInput) {
      throw new Error("github-proxy delivery requires exactly one repository");
    }
    if (Object.keys(permissions).length !== 1 || permissions.contents !== "write") {
      throw new Error("github-proxy delivery requires contents: write only");
    }
    const gitRef = branch.startsWith(branchRefPrefix) ? branch : `${branchRefPrefix}${branch}`;
    if (
      !validBranchRef(gitRef) ||
      ["refs/heads/main", "refs/heads/master"].includes(gitRef)
    ) {
      throw new Error("github-proxy delivery requires a safe, non-protected branch");
    }
    if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(expectedHead)) {
      throw new Error("github-proxy delivery requires an expected-head object ID");
    }
    proxyDelivery = { kind: "github_proxy", ref: gitRef, expected_old_oid: expectedHead };
  } else if (delivery !== "token" || branch || expectedHead) {
    throw new Error("branch and expected-head are supported only with github-proxy delivery");
  }

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
        ...((repository || repositories) && { "content-type": "application/json" }),
      },
      body: repository
        ? JSON.stringify({ repository, permissions, ...(proxyDelivery && { delivery: proxyDelivery }) })
        : repositories
          ? JSON.stringify({ repositories, permissions })
          : "",
    },
    "token exchange",
  );
  if (proxyDelivery) {
    if (exchangeResponse.token !== undefined) {
      if (typeof exchangeResponse.token === "string" && exchangeResponse.token.length > 0) {
        addMask(exchangeResponse.token, write);
        appendFileCommand(env.GITHUB_STATE, "token", exchangeResponse.token, appendFile, uuid);
        if (typeof exchangeResponse.expires_at === "string" && exchangeResponse.expires_at.length > 0) {
          appendFileCommand(env.GITHUB_STATE, "expiresAt", exchangeResponse.expires_at, appendFile, uuid);
        }
      }
      throw new Error("proxy capability response unexpectedly contained an installation token");
    }
    const capability = requiredString(exchangeResponse.capability, "proxy capability");
    if (
      !/^[A-Za-z0-9_-]+$/u.test(capability) ||
      capability.length > 8192
    ) {
      throw new Error("returned proxy capability is invalid");
    }
    const expiresAt = requiredString(exchangeResponse.expires_at, "proxy capability expiration");
    const returnedRepository = requiredString(exchangeResponse.repository, "repository");
    const returnedBranch = requiredString(exchangeResponse.branch, "proxy branch");
    const returnedHead = requiredString(exchangeResponse.expected_old_oid, "proxy expected head");
    const ref = requiredString(exchangeResponse.ref, "ref");
    if (
      returnedRepository !== repository ||
      returnedBranch !== proxyDelivery.ref ||
      returnedHead !== expectedHead
    ) {
      throw new Error("returned proxy capability does not match the requested scope");
    }
    for (const [name, value] of [
      ["capability", capability],
      ["expires-at", expiresAt],
      ["repository", returnedRepository],
      ["ref", ref],
      ["branch", returnedBranch],
      ["expected-head", returnedHead],
    ]) {
      appendFileCommand(env.GITHUB_OUTPUT, name, value, appendFile, uuid);
    }
    return;
  }

  const token = requiredString(exchangeResponse.token, "installation token");
  addMask(token, write);
  appendFileCommand(env.GITHUB_STATE, "token", token, appendFile, uuid);

  const expiresAt = requiredString(exchangeResponse.expires_at, "installation token expiration");
  appendFileCommand(env.GITHUB_STATE, "expiresAt", expiresAt, appendFile, uuid);
  const scopeOutputs = [];
  if (repositories) {
    const returned = exchangeResponse.repositories;
    if (
      exchangeResponse.repository !== undefined ||
      !Array.isArray(returned) ||
      returned.length !== repositories.length ||
      returned.some((value) => typeof value !== "string") ||
      !repositories.every((value) => returned.includes(value))
    ) {
      throw new Error("returned repositories do not match the requested repositories");
    }
    scopeOutputs.push(["repositories", returned.join("\n")]);
  } else {
    const returnedRepository = requiredString(exchangeResponse.repository, "repository");
    if (exchangeResponse.repositories !== undefined || (repository && returnedRepository !== repository)) {
      throw new Error("returned repository does not match the requested repository");
    }
    scopeOutputs.push(["repository", returnedRepository]);
  }
  const ref = requiredString(exchangeResponse.ref, "ref");

  for (const [name, value] of [
    ["token", token],
    ["expires-at", expiresAt],
    ...scopeOutputs,
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
