"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { validateExchangeUrl } = require("./validate-exchange-url.js");

test("accepts the exchange route for the configured audience", () => {
  assert.doesNotThrow(() =>
    validateExchangeUrl(
      "https://example.execute-api.us-east-2.amazonaws.com/exchange",
      "https://example.execute-api.us-east-2.amazonaws.com",
    ),
  );
  assert.doesNotThrow(() =>
    validateExchangeUrl(
      "https://broker.example:8443/stage/exchange",
      "https://broker.example:8443/stage/",
    ),
  );
});

test("rejects a misleading exchange URL with userinfo", () => {
  assert.throws(
    () =>
      validateExchangeUrl(
        "https://broker.example@attacker.example/exchange",
        "https://broker.example",
      ),
    /exchange-url must not contain credentials/,
  );
});

test("rejects a different exchange origin or route", () => {
  for (const exchange of [
    "https://attacker.example/exchange",
    "https://broker.example:8443/exchange",
    "https://broker.example/capture",
    "https://broker.example/exchange/",
  ]) {
    assert.throws(
      () => validateExchangeUrl(exchange, "https://broker.example"),
      /exchange-url must be the audience URL followed by \/exchange/,
    );
  }
});

test("rejects insecure and malformed URLs", () => {
  assert.throws(
    () => validateExchangeUrl("http://broker.example/exchange", "https://broker.example"),
    /exchange-url must use HTTPS/,
  );
  assert.throws(
    () => validateExchangeUrl("not a url", "https://broker.example"),
    /exchange-url must be a valid HTTPS URL/,
  );
  assert.throws(
    () => validateExchangeUrl("https://broker.example/exchange", "http://broker.example"),
    /audience must use HTTPS/,
  );
  assert.throws(
    () => validateExchangeUrl("https://broker.example/exchange", "not a url"),
    /audience must be a valid HTTPS URL/,
  );
});

test("rejects credentials, queries, and fragments", () => {
  for (const [exchange, audience, message] of [
    ["https://user:password@broker.example/exchange", "https://broker.example", /exchange-url must not contain credentials/],
    ["https://broker.example/exchange?token=secret", "https://broker.example", /exchange-url must not contain a query or fragment/],
    ["https://broker.example/exchange#token", "https://broker.example", /exchange-url must not contain a query or fragment/],
    ["https://broker.example/exchange", "https://user@broker.example", /audience must not contain credentials/],
    ["https://broker.example/exchange", "https://broker.example?token=secret", /audience must not contain a query or fragment/],
    ["https://broker.example/exchange", "https://broker.example#token", /audience must not contain a query or fragment/],
  ]) {
    assert.throws(() => validateExchangeUrl(exchange, audience), message);
  }
});
