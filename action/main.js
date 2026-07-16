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
    { method: "POST", headers: { authorization: `Bearer ${oidcToken}` }, body: "" },
    "token exchange",
  );
  const token = requiredString(exchangeResponse.token, "installation token");
  addMask(token, write);
  appendFileCommand(env.GITHUB_STATE, "token", token, appendFile, uuid);

  const expiresAt = requiredString(exchangeResponse.expires_at, "installation token expiration");
  appendFileCommand(env.GITHUB_STATE, "expiresAt", expiresAt, appendFile, uuid);
  const repository = requiredString(exchangeResponse.repository, "repository");
  const ref = requiredString(exchangeResponse.ref, "ref");

  for (const [name, value] of [
    ["token", token],
    ["expires-at", expiresAt],
    ["repository", repository],
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
