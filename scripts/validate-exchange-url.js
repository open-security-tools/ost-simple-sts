"use strict";

function parseHttpsUrl(value, name) {
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
  if (url.search || url.hash) {
    throw new Error(`${name} must not contain a query or fragment`);
  }

  return url;
}

function validateExchangeUrl(exchangeValue, audienceValue) {
  const exchange = parseHttpsUrl(exchangeValue, "exchange-url");
  const audience = parseHttpsUrl(audienceValue, "audience");
  const expectedPath = `${audience.pathname.replace(/\/$/, "")}/exchange`;

  if (exchange.origin !== audience.origin || exchange.pathname !== expectedPath) {
    throw new Error("exchange-url must be the audience URL followed by /exchange");
  }
}

if (require.main === module) {
  try {
    validateExchangeUrl(process.argv[2], process.argv[3]);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { validateExchangeUrl };
