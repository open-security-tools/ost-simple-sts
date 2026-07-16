"use strict";

const {
  addMask,
  addWarning,
  ensureProxyConfiguration,
  parseHttpsUrl,
  request,
} = require("./common.js");

async function run({
  env = process.env,
  fetchImpl = globalThis.fetch,
  now = Date.now,
  write = process.stdout.write.bind(process.stdout),
  warn = (value) => addWarning(value, write),
} = {}) {
  const token = env.STATE_token;
  if (!token) {
    return;
  }
  addMask(token, write);

  const expiresAt = Date.parse(env.STATE_expiresAt || "");
  if (Number.isFinite(expiresAt) && expiresAt <= now()) {
    return;
  }

  try {
    ensureProxyConfiguration(env);
    const apiUrl = parseHttpsUrl(env.GITHUB_API_URL || "https://api.github.com", "GITHUB_API_URL");
    apiUrl.pathname = `${apiUrl.pathname.replace(/\/$/, "")}/installation/token`;
    const response = await request(
      fetchImpl,
      apiUrl.toString(),
      {
        method: "DELETE",
        headers: {
          accept: "application/vnd.github+json",
          authorization: `Bearer ${token}`,
          "x-github-api-version": "2022-11-28",
        },
      },
      "token revocation",
    );
    if (!response.ok) {
      throw new Error(`token revocation request failed (${response.status})`);
    }
  } catch (error) {
    warn(`Unable to revoke the GitHub App installation token: ${error.message}`);
  }
}

if (require.main === module) {
  run().catch((error) => {
    addWarning(`Unable to revoke the GitHub App installation token: ${error.message}`);
  });
}

module.exports = { run };
