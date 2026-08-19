"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { run: runMain } = require("./main.js");
const { run: runPost } = require("./post.js");

const audience = "https://broker.example/stage";
const exchangeUrl = `${audience}/exchange`;
const expiresAt = "2026-07-15T20:00:00Z";

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function environment(overrides = {}) {
  return {
    "INPUT_EXCHANGE-URL": exchangeUrl,
    INPUT_AUDIENCE: audience,
    INPUT_REPOSITORY: "example/repository",
    INPUT_PERMISSIONS: "contents:write",
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://token.actions.example/oidc?request=123",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "request-token",
    GITHUB_OUTPUT: "outputs",
    GITHUB_STATE: "state",
    ...overrides,
  };
}

function memoryFiles() {
  const files = new Map();
  return {
    files,
    appendFile(file, value) {
      files.set(file, `${files.get(file) || ""}${value}`);
    },
  };
}

test("exchanges an OIDC token, masks credentials, and saves revocation state", async () => {
  const calls = [];
  const output = [];
  const { files, appendFile } = memoryFiles();
  const responses = [
    response({ value: "oidc%token\r\nmasked" }),
    response({
      token: "installation%token\r\nmasked",
      expires_at: expiresAt,
      repository: "example/repository",
      ref: "refs/heads/main",
    }),
  ];

  await runMain({
    env: environment(),
    appendFile,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return responses.shift();
    },
    uuid: () => "test-delimiter",
    write: (value) => output.push(value),
  });

  assert.equal(calls.length, 2);
  const oidcUrl = new URL(calls[0].url);
  assert.equal(oidcUrl.searchParams.get("request"), "123");
  assert.equal(oidcUrl.searchParams.get("audience"), audience);
  assert.equal(calls[0].options.headers.authorization, "bearer request-token");
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(calls[1].url, exchangeUrl);
  assert.equal(calls[1].options.method, "POST");
  assert.equal(calls[1].options.headers.authorization, "Bearer oidc%token\r\nmasked");
  assert.equal(calls[1].options.headers["content-type"], "application/json");
  assert.deepEqual(JSON.parse(calls[1].options.body), {
    repository: "example/repository",
    permissions: { contents: "write" },
  });
  assert.equal(calls[1].options.redirect, "error");
  assert.deepEqual(output, [
    "::add-mask::oidc%25token%0D%0Amasked\n",
    "::add-mask::installation%25token%0D%0Amasked\n",
  ]);

  assert.match(files.get("outputs"), /token<<ghadelimiter_test-delimiter\ninstallation%token\r\nmasked\nghadelimiter_test-delimiter/);
  assert.match(files.get("outputs"), /expires-at<<ghadelimiter_test-delimiter\n2026-07-15T20:00:00Z/);
  assert.match(files.get("outputs"), /repository<<ghadelimiter_test-delimiter\nexample\/repository/);
  assert.match(files.get("outputs"), /ref<<ghadelimiter_test-delimiter\nrefs\/heads\/main/);
  assert.match(files.get("state"), /token<<ghadelimiter_test-delimiter\ninstallation%token\r\nmasked/);
  assert.match(files.get("state"), /expiresAt<<ghadelimiter_test-delimiter\n2026-07-15T20:00:00Z/);
});

test("rejects an unsafe exchange URL before requesting an OIDC token", async () => {
  let called = false;
  await assert.rejects(
    runMain({
      env: environment({ "INPUT_EXCHANGE-URL": "https://broker.example@attacker.example/stage/exchange" }),
      fetchImpl: async () => {
        called = true;
      },
    }),
    /exchange-url must not contain credentials/,
  );
  assert.equal(called, false);
});

test("rejects an unexpected returned repository while preserving revocation state", async () => {
  const { files, appendFile } = memoryFiles();
  const responses = [
    response({ value: "oidc-token" }),
    response({
      token: "installation-token",
      expires_at: expiresAt,
      repository: "example/other",
      ref: "refs/heads/main",
    }),
  ];

  await assert.rejects(
    runMain({
      env: environment(),
      appendFile,
      fetchImpl: async () => responses.shift(),
      uuid: () => "test-delimiter",
      write: () => {},
    }),
    /returned repository does not match the requested repository/,
  );
  assert.match(files.get("state"), /token<<ghadelimiter_test-delimiter\ninstallation-token/);
  assert.equal(files.has("outputs"), false);
});

test("requires the OIDC permission and a safe runner token URL", async () => {
  await assert.rejects(
    runMain({ env: environment({ ACTIONS_ID_TOKEN_REQUEST_TOKEN: "" }) }),
    /id-token: write is required/,
  );
  await assert.rejects(
    runMain({ env: environment({ ACTIONS_ID_TOKEN_REQUEST_URL: "http://token.actions.example/oidc" }) }),
    /ACTIONS_ID_TOKEN_REQUEST_URL must use HTTPS/,
  );
});

test("rejects a partial or unsupported scope before requesting an OIDC token", async () => {
  let called = false;
  const fetchImpl = async () => {
    called = true;
  };

  await assert.rejects(
    runMain({ env: environment({ INPUT_REPOSITORY: "../other" }), fetchImpl }),
    /repository must be OWNER\/REPO/,
  );
  await assert.rejects(
    runMain({ env: environment({ INPUT_REPOSITORY: "" }), fetchImpl }),
    /repository or repositories and permissions must be provided together/,
  );
  await assert.rejects(
    runMain({ env: environment({ INPUT_PERMISSIONS: "members: read" }), fetchImpl }),
    /unknown repository permission: members/,
  );
  await assert.rejects(
    runMain({ env: environment({ INPUT_PERMISSIONS: "contents:write,actions:write" }), fetchImpl }),
    /one name: level entry per line/,
  );
  await assert.rejects(
    runMain({ env: environment({ INPUT_PERMISSIONS: "contents: admin" }), fetchImpl }),
    /invalid level for repository permission: contents/,
  );
  await assert.rejects(
    runMain({ env: environment({ INPUT_PERMISSIONS: "contents: read\ncontents: write" }), fetchImpl }),
    /duplicate repository permission: contents/,
  );
  assert.equal(called, false);
});

test("sends newline-delimited target repositories as an exact multi-repository request", async () => {
  const calls = [];
  const { files, appendFile } = memoryFiles();
  const responses = [
    response({ value: "oidc-token" }),
    response({
      token: "installation-token",
      expires_at: expiresAt,
      repositories: ["astral-sh/uv", "astral-sh/uv-dev"],
      ref: "refs/heads/main",
    }),
  ];

  await runMain({
    env: environment({
      INPUT_REPOSITORY: "",
      INPUT_REPOSITORIES: "astral-sh/uv\nastral-sh/uv-dev\n",
      INPUT_PERMISSIONS: "contents: write\npull_requests: write",
    }),
    appendFile,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return responses.shift();
    },
    uuid: () => "test-delimiter",
    write: () => {},
  });

  assert.deepEqual(JSON.parse(calls[1].options.body), {
    repositories: ["astral-sh/uv", "astral-sh/uv-dev"],
    permissions: { contents: "write", pull_requests: "write" },
  });
  assert.match(
    files.get("outputs"),
    /repositories<<ghadelimiter_test-delimiter\nastral-sh\/uv\nastral-sh\/uv-dev\nghadelimiter_test-delimiter/,
  );
  assert.doesNotMatch(files.get("outputs"), /\nrepository<</);
});

test("rejects mixed, invalid, and duplicate multi-repository inputs before requesting OIDC", async () => {
  let called = false;
  const fetchImpl = async () => {
    called = true;
  };

  await assert.rejects(
    runMain({
      env: environment({
        INPUT_REPOSITORIES: "astral-sh/uv\nastral-sh/uv-dev",
      }),
      fetchImpl,
    }),
    /repository and repositories are mutually exclusive/,
  );
  await assert.rejects(
    runMain({
      env: environment({
        INPUT_REPOSITORY: "",
        INPUT_REPOSITORIES: "astral-sh/uv",
      }),
      fetchImpl,
    }),
    /repositories must contain at least two OWNER\/REPO entries/,
  );
  await assert.rejects(
    runMain({
      env: environment({
        INPUT_REPOSITORY: "",
        INPUT_REPOSITORIES: "astral-sh/uv\n../other",
      }),
      fetchImpl,
    }),
    /repositories must contain one OWNER\/REPO entry per line/,
  );
  await assert.rejects(
    runMain({
      env: environment({
        INPUT_REPOSITORY: "",
        INPUT_REPOSITORIES: "astral-sh/uv\nASTRAL-SH/UV",
      }),
      fetchImpl,
    }),
    /duplicate repository: ASTRAL-SH\/UV/,
  );
  assert.equal(called, false);
});

test("rejects an unexpected returned repository set while preserving revocation state", async () => {
  for (const repositories of [
    ["astral-sh/uv"],
    ["astral-sh/uv", "astral-sh/other"],
    ["astral-sh/uv", "astral-sh/uv", "astral-sh/uv-dev"],
    ["astral-sh/uv", "astral-sh/uv"],
  ]) {
    const { files, appendFile } = memoryFiles();
    const responses = [
      response({ value: "oidc-token" }),
      response({
        token: "installation-token",
        expires_at: expiresAt,
        repositories,
        ref: "refs/heads/main",
      }),
    ];

    await assert.rejects(
      runMain({
        env: environment({
          INPUT_REPOSITORY: "",
          INPUT_REPOSITORIES: "astral-sh/uv\nastral-sh/uv-dev",
        }),
        appendFile,
        fetchImpl: async () => responses.shift(),
        uuid: () => "test-delimiter",
        write: () => {},
      }),
      /returned repositories do not match the requested repositories/,
    );
    assert.match(files.get("state"), /token<<ghadelimiter_test-delimiter\ninstallation-token/);
    assert.equal(files.has("outputs"), false);
  }
});

test("sends multiple newline-delimited repository permissions as a JSON map", async () => {
  const calls = [];
  const responses = [
    response({ value: "oidc-token" }),
    response({
      token: "installation-token",
      expires_at: expiresAt,
      repository: "example/repository",
      ref: "refs/heads/main",
    }),
  ];

  await runMain({
    env: environment({ INPUT_PERMISSIONS: "contents: write\npull_requests: read\n" }),
    appendFile: () => {},
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return responses.shift();
    },
    write: () => {},
  });

  assert.deepEqual(JSON.parse(calls[1].options.body), {
    repository: "example/repository",
    permissions: { contents: "write", pull_requests: "read" },
  });
});

test("preserves the legacy empty exchange request when no scope inputs are provided", async () => {
  const calls = [];
  const responses = [
    response({ value: "oidc-token" }),
    response({
      token: "installation-token",
      expires_at: expiresAt,
      repository: "example/repository",
      ref: "refs/heads/main",
    }),
  ];

  await runMain({
    env: environment({ INPUT_REPOSITORY: "", INPUT_PERMISSIONS: "" }),
    appendFile: () => {},
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return responses.shift();
    },
    write: () => {},
  });

  assert.equal(calls[1].options.body, "");
  assert.equal(calls[1].options.headers["content-type"], undefined);
});

test("requires Node proxy support when a proxy is configured", async () => {
  await assert.rejects(
    runMain({ env: environment({ HTTPS_PROXY: "http://proxy.example:8080" }) }),
    /NODE_USE_ENV_PROXY=1/,
  );
});

test("does not retry a failed token exchange or expose its response", async () => {
  let calls = 0;
  await assert.rejects(
    runMain({
      env: environment({ INPUT_REPOSITORY: "", INPUT_PERMISSIONS: "" }),
      fetchImpl: async () => {
        calls += 1;
        return calls === 1 ? response({ value: "oidc-token" }) : response({ token: "secret" }, 500);
      },
      write: () => {},
    }),
    /^Error: token exchange request failed \(500\)$/,
  );
  assert.equal(calls, 2);
});

test("saves an issued token for revocation before validating the remaining response", async () => {
  const output = [];
  const { files, appendFile } = memoryFiles();
  const responses = [
    response({ value: "oidc-token" }),
    response({ token: "installation-token", expires_at: expiresAt }),
  ];

  await assert.rejects(
    runMain({
      env: environment(),
      appendFile,
      fetchImpl: async () => responses.shift(),
      uuid: () => "test-delimiter",
      write: (value) => output.push(value),
    }),
    /repository was not returned by the service/,
  );
  assert.deepEqual(output, ["::add-mask::oidc-token\n", "::add-mask::installation-token\n"]);
  assert.match(files.get("state"), /token<<ghadelimiter_test-delimiter\ninstallation-token/);
  assert.match(files.get("state"), /expiresAt<<ghadelimiter_test-delimiter\n2026-07-15T20:00:00Z/);
  assert.equal(files.has("outputs"), false);
});

test("rejects an output delimiter embedded in a returned value", async () => {
  const { files, appendFile } = memoryFiles();
  const responses = [
    response({ value: "oidc-token" }),
    response({
      token: "installation-token",
      expires_at: expiresAt,
      repository: "example/repository\nghadelimiter_test-delimiter\ninjected=value",
      ref: "refs/heads/main",
    }),
  ];

  await assert.rejects(
    runMain({
      env: environment({ INPUT_REPOSITORY: "", INPUT_PERMISSIONS: "" }),
      appendFile,
      fetchImpl: async () => responses.shift(),
      uuid: () => "test-delimiter",
      write: () => {},
    }),
    /unexpected delimiter in repository/,
  );
  assert.match(files.get("state"), /token<<ghadelimiter_test-delimiter\ninstallation-token/);
  assert.doesNotMatch(files.get("outputs"), /injected=value/);
});

test("revokes the installation token against the configured GitHub API", async () => {
  const calls = [];
  const output = [];
  await runPost({
    env: {
      STATE_token: "installation-token",
      STATE_expiresAt: expiresAt,
      GITHUB_API_URL: "https://github.example/api/v3/",
      HTTPS_PROXY: "http://proxy.example:8080",
      NODE_USE_ENV_PROXY: "1",
    },
    now: () => Date.parse("2026-07-15T19:30:00Z"),
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return response(null, 204);
    },
    write: (value) => output.push(value),
    warn: assert.fail,
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://github.example/api/v3/installation/token");
  assert.equal(calls[0].options.method, "DELETE");
  assert.equal(calls[0].options.headers.authorization, "Bearer installation-token");
  assert.equal(calls[0].options.headers.accept, "application/vnd.github+json");
  assert.equal(calls[0].options.headers["x-github-api-version"], "2022-11-28");
  assert.equal(calls[0].options.redirect, "error");
  assert.deepEqual(output, ["::add-mask::installation-token\n"]);
});

test("skips revocation when the token is missing or already expired", async () => {
  let called = false;
  const fetchImpl = async () => {
    called = true;
  };

  await runPost({ env: {}, fetchImpl, write: () => {}, warn: assert.fail });
  await runPost({
    env: { STATE_token: "installation-token", STATE_expiresAt: expiresAt },
    now: () => Date.parse("2026-07-15T20:00:00Z"),
    fetchImpl,
    write: () => {},
    warn: assert.fail,
  });
  assert.equal(called, false);
});

test("warns without failing the job when revocation cannot complete", async () => {
  const warnings = [];
  await runPost({
    env: { STATE_token: "installation-token", STATE_expiresAt: expiresAt },
    now: () => Date.parse("2026-07-15T19:30:00Z"),
    fetchImpl: async () => response({ token: "must-not-be-logged" }, 403),
    write: () => {},
    warn: (value) => warnings.push(value),
  });
  assert.deepEqual(warnings, [
    "Unable to revoke the GitHub App installation token: token revocation request failed (403)",
  ]);
});

test("emits a visible GitHub warning annotation when revocation fails", async () => {
  const output = [];
  await runPost({
    env: { STATE_token: "installation-token", STATE_expiresAt: expiresAt },
    now: () => Date.parse("2026-07-15T19:30:00Z"),
    fetchImpl: async () => response(null, 503),
    write: (value) => output.push(value),
  });
  assert.deepEqual(output, [
    "::add-mask::installation-token\n",
    "::warning::Unable to revoke the GitHub App installation token: token revocation request failed (503)\n",
  ]);
});

test("warns and makes no request for an unsafe GitHub API URL", async () => {
  const warnings = [];
  let called = false;
  await runPost({
    env: {
      STATE_token: "installation-token",
      STATE_expiresAt: expiresAt,
      GITHUB_API_URL: "https://api.github.com@attacker.example",
    },
    now: () => Date.parse("2026-07-15T19:30:00Z"),
    fetchImpl: async () => {
      called = true;
    },
    write: () => {},
    warn: (value) => warnings.push(value),
  });
  assert.equal(called, false);
  assert.deepEqual(warnings, [
    "Unable to revoke the GitHub App installation token: GITHUB_API_URL must not contain credentials",
  ]);
});

test("rejects administration write before requesting credentials", async () => {
  await assert.rejects(runMain({ env: environment({ INPUT_PERMISSIONS: "administration: write" }),
    fetchImpl: assert.fail }), /administration is limited to read/);
});
