/**
 * augment.mjs
 *
 * Reads api-calls-01.json and enriches every entry with three new fields:
 *
 *   graphApiUrl     – best documented public Microsoft API URL (with real
 *                     captured IDs substituted in), or null when no public
 *                     equivalent exists.
 *   graphApiVersion – "defender" | "v1.0" | "beta" | "sentinel" | "n/a"
 *   graphApiNotes   – human-readable notes: confidence, required scope,
 *                     relevant docs links, or "no public API" explanation.
 *
 * Proxy calls are matched against the ordered rules in api-mapping.json.
 * Direct Graph calls (isProxy: false) are passed through unchanged.
 *
 * Output: api-calls-01-augmented.json
 *
 * Usage: node research/augment.mjs
 *
 * No npm dependencies — uses only Node.js built-ins.
 */

import { readFileSync, writeFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const INPUT_FILE  = resolve(__dirname, "api-calls-01.json");
const RULES_FILE  = resolve(__dirname, "api-mapping.json");
const OUTPUT_FILE = resolve(__dirname, "api-calls-01-augmented.json");

// ── Load inputs ───────────────────────────────────────────────────────────────

const entries = JSON.parse(readFileSync(INPUT_FILE, "utf8"));
const rules   = JSON.parse(readFileSync(RULES_FILE, "utf8"));

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Strip the query string and any trailing slashes from a URL path so that
 * regex patterns can anchor to $ without worrying about these variants.
 *
 * Examples:
 *   "/apiproxy/mtp/autoIr/incidents/33/?pageSize=1" → "/apiproxy/mtp/autoIr/incidents/33"
 *   "/apiproxy/mtp/huntingService/queries/?type=scheduled" → "/apiproxy/mtp/huntingService/queries"
 */
function cleanPath(rawPath) {
    return rawPath.split("?")[0].replace(/\/+$/, "");
}

/**
 * Apply the first matching rule from api-mapping.json to a proxy entry.
 * Substitutes the first regex capture group for the {id} placeholder in
 * graphApiUrl templates so the output URL carries the real captured ID.
 *
 * @param {object} entry  A RequestEntry object with isProxy === true.
 * @returns {{ graphApiUrl: string|null, graphApiVersion: string, graphApiNotes: string }}
 */
function mapProxyEntry(entry) {
    const path = cleanPath(entry.path);

    for (const rule of rules) {
        const regex = new RegExp(rule.proxyPathPattern, "i");
        const match = regex.exec(path);

        if (match) {
            let url = rule.graphApiUrl;

            // Substitute the first capture group (the resource ID) into {id}
            if (url && match[1]) {
                url = url.replace("{id}", match[1]);
            }

            return {
                graphApiUrl:     url,
                graphApiVersion: rule.graphApiVersion,
                graphApiNotes:   rule.graphApiNotes,
            };
        }
    }

    // No rule matched — should not happen with a complete rules file, but
    // guard defensively so the output is always consistent.
    return {
        graphApiUrl:     null,
        graphApiVersion: "n/a",
        graphApiNotes:   "No mapping rule matched. Likely a portal-internal API with no public equivalent.",
    };
}

// ── Augment ───────────────────────────────────────────────────────────────────

const augmented = entries.map((entry) => {
    let mapping;

    if (!entry.isProxy) {
        // Direct Graph API call — the captured URL is already the public URL.
        mapping = {
            graphApiUrl:     entry.url,
            graphApiVersion: entry.version ?? "v1.0",
            graphApiNotes:   "Direct Microsoft Graph API call. No proxy mapping needed.",
        };
    } else {
        mapping = mapProxyEntry(entry);
    }

    return {
        ...entry,
        graphApiUrl:     mapping.graphApiUrl,
        graphApiVersion: mapping.graphApiVersion,
        graphApiNotes:   mapping.graphApiNotes,
    };
});

// ── Write output ──────────────────────────────────────────────────────────────

writeFileSync(OUTPUT_FILE, JSON.stringify(augmented, null, 2), "utf8");

// ── Summary ───────────────────────────────────────────────────────────────────

const total       = augmented.length;
const withApi     = augmented.filter((e) => e.graphApiUrl !== null).length;
const withoutApi  = augmented.filter((e) => e.graphApiUrl === null).length;
const unmatched   = augmented.filter(
    (e) => e.graphApiNotes?.startsWith("No mapping rule matched"),
).length;

const byVersion = augmented.reduce((acc, e) => {
    acc[e.graphApiVersion] = (acc[e.graphApiVersion] ?? 0) + 1;
    return acc;
}, {});

console.log(`\nDefender XRay — API mapping augmentation`);
console.log(`${"─".repeat(45)}`);
console.log(`Input entries   : ${total}`);
console.log(`With public API : ${withApi}`);
console.log(`No public API   : ${withoutApi}`);
if (unmatched > 0) {
    console.warn(`⚠  Unmatched rules: ${unmatched} (check api-mapping.json for gaps)`);
}
console.log(`\nBreakdown by graphApiVersion:`);
for (const [version, count] of Object.entries(byVersion).sort()) {
    console.log(`  ${version.padEnd(10)} ${count}`);
}
console.log(`\nOutput: ${OUTPUT_FILE}`);
