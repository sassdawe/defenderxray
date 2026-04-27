/**
 * redaction.js
 *
 * Shared redaction utilities used by panel rendering and export code.
 * This module intentionally has no DOM or Chrome API dependencies so it can
 * be regression-tested with Node's built-in test runner.
 */

(function (root, factory) {
    if (typeof module === "object" && module.exports) {
        module.exports = factory();
    } else {
        root.Redaction = factory();
    }
}(typeof globalThis !== "undefined" ? globalThis : this, function () {
    "use strict";

    // Keys and headers that commonly carry session credentials or secrets.
    const SENSITIVE_KEY_RE = /(token|cookie|session|auth|secret|password|passwd|api[_-]?key|client[_-]?secret|csrf|xsrf)/i;
    const SENSITIVE_QUERY_KEY_RE = /^(token|access[_-]?token|refresh[_-]?token|id[_-]?token|session(?:id)?|auth(?:orization)?|csrf(?:token)?|xsrf(?:token)?|api[_-]?key|client[_-]?secret)$/i;
    const SENSITIVE_HEADER_NAME_RE = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|x-session-id)$/i;

    /**
     * Build a sanitized request clone safe for UI details and JSON export.
     * @param {object} req
     * @returns {object}
     */
    function sanitizeRequestEntry(req) {
        return {
            ...req,
            url: redactSensitiveQueryParams(req.url),
            path: redactSensitiveQueryParams(req.path),
            publicApiUrl: req.publicApiUrl ? redactSensitiveQueryParams(req.publicApiUrl) : null,
            requestHeaders: sanitizeHeaders(req.requestHeaders),
            responseHeaders: sanitizeHeaders(req.responseHeaders),
            requestBody: sanitizePayload(req.requestBody),
            responseBody: sanitizePayload(req.responseBody),
        };
    }

    /**
     * Redact sensitive header values while keeping useful header names.
     * @param {Array<{name: string, value: string}>} headers
     * @returns {Array<{name: string, value: string}>}
     */
    function sanitizeHeaders(headers) {
        if (!headers || headers.length === 0) return [];
        return headers.map(function (h) {
            return {
                name: h.name,
                value: sanitizeHeaderValue(h.name, h.value),
            };
        });
    }

    /**
     * Redact header values that commonly contain credentials.
     * @param {string} name
     * @param {string} value
     * @returns {string}
     */
    function sanitizeHeaderValue(name, value) {
        const str = String(value ?? "");
        if (SENSITIVE_HEADER_NAME_RE.test(String(name || ""))) return "[REDACTED]";
        return redactSensitiveText(str);
    }

    /**
     * Redact sensitive keys from a JSON payload string when possible.
     * Falls back to regex-based text masking for non-JSON payloads.
     * @param {string|null} payload
     * @returns {string|null}
     */
    function sanitizePayload(payload) {
        if (!payload) return payload;
        try {
            const parsed = JSON.parse(payload);
            const redacted = redactSensitiveObject(parsed);
            return JSON.stringify(redacted, null, 2);
        } catch {
            return redactSensitiveText(payload);
        }
    }

    /**
     * Recursively redact sensitive object keys.
     * @param {any} value
     * @returns {any}
     */
    function redactSensitiveObject(value) {
        if (Array.isArray(value)) {
            return value.map(redactSensitiveObject);
        }
        if (!value || typeof value !== "object") {
            return value;
        }
        const output = {};
        Object.keys(value).forEach(function (key) {
            if (SENSITIVE_KEY_RE.test(key)) {
                output[key] = "[REDACTED]";
            } else {
                output[key] = redactSensitiveObject(value[key]);
            }
        });
        return output;
    }

    /**
     * Redact sensitive query values in URLs and URL-like paths.
     * @param {string} input
     * @returns {string}
     */
    function redactSensitiveQueryParams(input) {
        if (!input) return input;

        const tryRedact = function (url, isRelativePath) {
            let changed = false;
            url.searchParams.forEach(function (_value, key) {
                if (SENSITIVE_QUERY_KEY_RE.test(key)) {
                    changed = true;
                    url.searchParams.set(key, "[REDACTED]");
                }
            });
            if (!changed) return null;
            if (isRelativePath) return `${url.pathname}${url.search}${url.hash}`;
            return url.toString();
        };

        try {
            const parsed = new URL(input);
            const out = tryRedact(parsed, false);
            if (out !== null) return out;
        } catch {
            // Ignore and try relative path parsing below.
        }

        if (input.startsWith("/")) {
            try {
                const parsed = new URL(input, "https://placeholder.local");
                const out = tryRedact(parsed, true);
                if (out !== null) return out;
            } catch {
                // Ignore and use regex fallback below.
            }
        }

        return input.replace(
            /([?&])(token|access[_-]?token|refresh[_-]?token|id[_-]?token|session(?:id)?|auth(?:orization)?|csrf(?:token)?|xsrf(?:token)?|api[_-]?key|client[_-]?secret)=([^&#]*)/gi,
            "$1$2=[REDACTED]"
        );
    }

    /**
     * Redact common secret-like value patterns from free-form text.
     * @param {string} input
     * @returns {string}
     */
    function redactSensitiveText(input) {
        if (!input) return input;
        return input
            .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[REDACTED]")
            .replace(/((?:access|refresh|id)?[_-]?token|session(?:id)?|auth(?:orization)?|csrf(?:token)?|xsrf(?:token)?|api[_-]?key|client[_-]?secret|password|passwd)\s*[:=]\s*(["'])?[^"'\s&;,]+\2?/gi, "$1=[REDACTED]");
    }

    return {
        SENSITIVE_KEY_RE,
        SENSITIVE_QUERY_KEY_RE,
        SENSITIVE_HEADER_NAME_RE,
        sanitizeRequestEntry,
        sanitizeHeaders,
        sanitizeHeaderValue,
        sanitizePayload,
        redactSensitiveObject,
        redactSensitiveQueryParams,
        redactSensitiveText,
    };
}));
