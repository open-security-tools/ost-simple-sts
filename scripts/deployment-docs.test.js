"use strict";
const assert = require("node:assert/strict");
const { existsSync, readFileSync } = require("node:fs");
const test = require("node:test");
const { resolve } = require("node:path");
const root = resolve(__dirname, "..");
const read = (path) => readFileSync(resolve(root, path), "utf8");

test("manual deployment uses explicit parameters and change-set review", () => {
  for (const path of ["scripts/deploy.sh", "scripts/deploy-secrets.sh", ".env.example", "samconfig.toml"]) {
    assert.equal(existsSync(resolve(root, path)), false, path);
  }
  assert.doesNotMatch(read("Makefile"), /^deploy(?:-secrets)?:/m);
  assert.match(read("README.md"), /--confirm-changeset/);
  assert.match(read("README.md"), /--no-fail-on-empty-changeset/);
  assert.match(read("README.md"), /AppPrivateKeySecretName=/);
  for (const ignored of [".env", ".env.local", ".secrets/"]) {
    assert.ok(read(".gitignore").split("\n").includes(ignored));
  }
});
