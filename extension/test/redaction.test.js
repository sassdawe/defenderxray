const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const Redaction = require("../redaction.js");

const fixturesDir = path.join(__dirname, "fixtures");

function readFixture(fileName) {
    const fullPath = path.join(fixturesDir, fileName);
    return JSON.parse(fs.readFileSync(fullPath, "utf8"));
}

const headerFixtures = readFixture("headers.json");
const payloadFixtures = readFixture("payloads.json");
const queryFixtures = readFixture("queries.json");
const requestEntryFixture = readFixture("request-entry.json");
const secretsFixture = readFixture("secrets.json");

test("sanitizeHeaderValue redacts known sensitive headers", function () {
    headerFixtures.sensitive.forEach(function (item) {
        assert.equal(Redaction.sanitizeHeaderValue(item.name, item.value), "[REDACTED]");
    });
});

test("sanitizeHeaderValue preserves non-sensitive headers", function () {
    headerFixtures.nonSensitive.forEach(function (item) {
        const value = Redaction.sanitizeHeaderValue(item.name, item.value);
        assert.equal(value, item.value);
    });
});

test("sanitizeHeaders preserves shape while redacting values", function () {
    const headers = headerFixtures.sensitive.concat(headerFixtures.nonSensitive);
    const sanitized = Redaction.sanitizeHeaders(headers);

    assert.equal(sanitized.length, headers.length);
    assert.equal(sanitized[0].name, headers[0].name);
    assert.equal(sanitized[0].value, "[REDACTED]");
    assert.equal(sanitized[sanitized.length - 1].value, headers[headers.length - 1].value);
});

test("sanitizePayload redacts nested JSON sensitive keys", function () {
    const payload = JSON.stringify(payloadFixtures.nestedJson);

    const sanitized = Redaction.sanitizePayload(payload);
    const parsed = JSON.parse(sanitized);

    assert.equal(parsed.id, "evt-1");
    assert.equal(parsed.auth, "[REDACTED]");
    assert.equal(parsed.nested[0].sessionId, "[REDACTED]");
    assert.equal(parsed.nested[1].keep, "ok");
    assert.equal(parsed.profile.displayName, "Example User");
});

test("sanitizePayload redacts arrays containing sensitive keys", function () {
    const payload = JSON.stringify(payloadFixtures.arrayJson);
    const sanitized = Redaction.sanitizePayload(payload);
    const parsed = JSON.parse(sanitized);

    assert.equal(parsed[0].api_key, "[REDACTED]");
    assert.equal(parsed[0].name, "first");
    assert.equal(parsed[1].token, "[REDACTED]");
    assert.equal(parsed[1].name, "second");
});

test("sanitizePayload redacts non-JSON bearer and token text", function () {
    const raw = payloadFixtures.nonJsonRaw;
    const sanitized = Redaction.sanitizePayload(raw);

    assert.match(sanitized, /Authorization\s*[:=]\s*\[REDACTED\]/i);
    assert.match(sanitized, /\[REDACTED\]/i);
    assert.match(sanitized, /api_key=\[REDACTED\]/i);
    assert.ok(!sanitized.includes("verysecrettoken"));
    assert.ok(!sanitized.includes("abc123"));
});

test("redactSensitiveQueryParams masks sensitive query parameters", function () {
    const url = queryFixtures.absoluteUrl;
    const sanitized = Redaction.redactSensitiveQueryParams(url);

    assert.match(sanitized, /access_token=%5BREDACTED%5D|access_token=\[REDACTED\]/i);
    assert.match(sanitized, /sessionId=%5BREDACTED%5D|sessionId=\[REDACTED\]/i);
    assert.match(sanitized, /(?:\$top|%24top)=10/i);
    assert.ok(!sanitized.includes("access_token=abc"));
    assert.ok(!sanitized.includes("sessionId=s1"));
});

test("redactSensitiveQueryParams handles relative paths", function () {
    const sanitized = Redaction.redactSensitiveQueryParams(queryFixtures.relativePath);

    assert.match(sanitized, /^\/v1\.0\/security\/incidents\?/);
    assert.match(sanitized, /api_key=%5BREDACTED%5D|api_key=\[REDACTED\]/i);
    assert.match(sanitized, /(?:\$count|%24count)=true/i);
    assert.ok(!sanitized.includes("api_key=xyz"));
});

test("redactSensitiveQueryParams redacts repeated sensitive keys", function () {
    const sanitized = Redaction.redactSensitiveQueryParams(queryFixtures.multiValue);
    const redactedMatches = sanitized.match(/token=%5BREDACTED%5D|token=\[REDACTED\]/gi) || [];

    // URLSearchParams.set normalizes duplicate keys into a single value.
    assert.ok(redactedMatches.length >= 1);
    assert.ok(!sanitized.includes("token=one"));
    assert.ok(!sanitized.includes("token=two"));
    assert.match(sanitized, /keep=ok/i);
});

test("sanitizeRequestEntry redacts headers, bodies, and query params", function () {
    const req = JSON.parse(JSON.stringify(requestEntryFixture));
    const originalSnapshot = JSON.stringify(req);

    const sanitized = Redaction.sanitizeRequestEntry(req);

    assert.equal(sanitized.requestHeaders[0].value, "[REDACTED]");
    assert.equal(sanitized.requestHeaders[1].value, "application/json");
    assert.equal(sanitized.responseHeaders[0].value, "[REDACTED]");

    assert.ok(!sanitized.url.includes("token=abc"));
    assert.ok(!sanitized.path.includes("api_key=xyz"));
    assert.ok(!sanitized.publicApiUrl.includes("session=aaa"));

    const reqBodyObj = JSON.parse(sanitized.requestBody);
    const resBodyObj = JSON.parse(sanitized.responseBody);
    assert.equal(reqBodyObj.clientSecret, "[REDACTED]");
    assert.equal(reqBodyObj.keep, true);
    assert.equal(resBodyObj.accessToken, "[REDACTED]");
    assert.equal(resBodyObj.value, 12);

    // Ensure sanitizeRequestEntry does not mutate the source object.
    assert.equal(JSON.stringify(req), originalSnapshot);

    const serialized = JSON.stringify(sanitized);
    ["topsecret", "supersecret", "res-secret", "abc", "xyz", "aaa"].forEach(function (secret) {
        assert.ok(!serialized.includes(secret));
    });
});

test("leak sentinel: fixture secrets never appear after sanitization", function () {
    const outputs = [];
    outputs.push(JSON.stringify(Redaction.sanitizeHeaders(headerFixtures.sensitive.concat(headerFixtures.nonSensitive))));
    outputs.push(Redaction.sanitizePayload(JSON.stringify(payloadFixtures.nestedJson)));
    outputs.push(Redaction.sanitizePayload(payloadFixtures.nonJsonRaw));
    outputs.push(Redaction.redactSensitiveQueryParams(queryFixtures.absoluteUrl));
    outputs.push(Redaction.redactSensitiveQueryParams(queryFixtures.relativePath));
    outputs.push(JSON.stringify(Redaction.sanitizeRequestEntry(requestEntryFixture)));

    const combined = outputs.join("\n");
    secretsFixture.mustNotLeak.forEach(function (secret) {
        assert.ok(!combined.includes(secret), `secret leaked: ${secret}`);
    });
});
