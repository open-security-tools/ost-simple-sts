"use strict";

const { randomUUID } = require("node:crypto");
const { appendFileSync } = require("node:fs");

const REQUEST_TIMEOUT_MS = 15_000;

function parseHttpsUrl(value, name, allowQuery = false) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be a valid HTTPS URL`);
  }

  if (url.protocol !== "https:") {
    throw new Error(`${name} must use HTTPS`);
  }
  if (url.username || url.password) {
    throw new Error(`${name} must not contain credentials`);
  }
  if ((!allowQuery && url.search) || url.hash) {
    throw new Error(`${name} must not contain a query or fragment`);
  }

  return url;
}

function ensureProxyConfiguration(env) {
  const proxyConfigured = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"].some(
    (name) => env[name],
  );
  if (proxyConfigured && env.NODE_USE_ENV_PROXY !== "1") {
    throw new Error("set NODE_USE_ENV_PROXY=1 when an HTTP proxy is configured");
  }
}

function writeCommand(command, value, write = process.stdout.write.bind(process.stdout)) {
  const escaped = value.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
  write(`::${command}::${escaped}\n`);
}

function addMask(value, write) {
  writeCommand("add-mask", value, write);
}

function addWarning(value, write) {
  writeCommand("warning", value, write);
}

function appendFileCommand(file, name, value, appendFile = appendFileSync, uuid = randomUUID) {
  if (!file) {
    throw new Error(`missing file for ${name}`);
  }

  const delimiter = `ghadelimiter_${uuid()}`;
  if (value.includes(delimiter)) {
    throw new Error(`unexpected delimiter in ${name}`);
  }
  appendFile(file, `${name}<<${delimiter}\n${value}\n${delimiter}\n`, "utf8");
}

async function request(fetchImpl, url, options, description) {
  try {
    return await fetchImpl(url, {
      ...options,
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    throw new Error(`${description} request failed`);
  }
}

async function requestJson(fetchImpl, url, options, description) {
  const response = await request(fetchImpl, url, options, description);
  if (!response.ok) {
    const error = new Error(`${description} request failed (${response.status})`);
    if (description === "token exchange" && response.status === 503) {
      const retry = response.headers?.get("retry-after");
      const body = await response.json().catch(() => null);
      if (body?.code === "github_rate_limited" && /^[1-9][0-9]*$/u.test(retry || "")) {
        error.retryAfter = Number(retry);
      }
    }
    throw error;
  }

  try {
    return await response.json();
  } catch {
    throw new Error(`${description} response was not valid JSON`);
  }
}

function requiredString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} was not returned by the service`);
  }
  return value;
}

module.exports = {
  addMask,
  addWarning,
  appendFileCommand,
  ensureProxyConfiguration,
  parseHttpsUrl,
  request,
  requestJson,
  requiredString,
};
