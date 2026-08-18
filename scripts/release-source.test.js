"use strict";
const assert = require("node:assert/strict");
const { execFileSync, spawnSync } = require("node:child_process");
const { mkdtempSync, readFileSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { resolve, join } = require("node:path");
const test = require("node:test");
const root = resolve(__dirname, "..");

test("release source must be reachable from main", () => {
  const cwd = mkdtempSync(join(tmpdir(), "sts-release-"));
  const git = (...args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  const commit = () => git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-m", "test");
  const check = (ref) => spawnSync("bash", [resolve(__dirname, "validate-release-source.sh"), ref], { cwd }).status;
  try {
    git("init", "--quiet"); commit();
    const main = git("rev-parse", "HEAD");
    git("update-ref", "refs/remotes/origin/main", main);
    assert.equal(check(main), 0);
    commit();
    assert.notEqual(check("HEAD"), 0);
    assert.notEqual(check("not-a-commit"), 0);
    git("update-ref", "refs/remotes/origin/main", "HEAD");
    assert.equal(check(main), 0);
  } finally { rmSync(cwd, { recursive: true, force: true }); }
});

test("publishing depends on reusable CI and source validation", () => {
  const ci = readFileSync(join(root, ".github/workflows/ci.yml"), "utf8");
  const publish = readFileSync(join(root, ".github/workflows/publish.yml"), "utf8");
  assert.match(ci, /^  workflow_call:/m);
  assert.match(publish, /fetch-depth: 0/);
  assert.match(publish, /uses: \.\/\.github\/workflows\/ci\.yml/);
  assert.match(publish, /build:\n    needs: \[release-source, checks\]/);
  assert.match(publish, /publish:\n    name:[^\n]+\n    needs: build/);
});
