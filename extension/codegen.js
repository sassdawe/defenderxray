/**
 * codegen.js
 *
 * Pure code-generation utilities for Defender XRay.
 *
 * Converts a captured Microsoft API request into a ready-to-run script in one
 * of four languages / SDKs.  Handles two request origins:
 *
 *   Direct Graph API (graph.microsoft.com)
 *     PowerShell  – Microsoft Graph PowerShell SDK (Invoke-MgGraphRequest)
 *     Python      – requests library + MSAL authentication
 *     C#          – HttpClient + Azure.Identity (ClientSecretCredential)
 *     JavaScript  – Microsoft Graph JavaScript SDK + @azure/identity
 *
 *   Defender XDR portal proxy (security.microsoft.com/apiproxy/*)
 *     The portal routes internal calls through /apiproxy/{proxy}/{service}/{resource}.
 *     The generated script targets the equivalent Microsoft 365 Defender REST API
 *     at https://api.security.microsoft.com using the appropriate auth scope.
 *     PowerShell  – MSAL.PS + Invoke-RestMethod
 *     Python      – requests + MSAL (scope: api.security.microsoft.com/.default)
 *     C#          – HttpClient + Azure.Identity (same, different scope)
 *     JavaScript  – @azure/identity + fetch API
 *
 * Each generator function receives a `RequestEntry` object (see panel.js)
 * and returns a formatted, human-readable string ready to paste into an IDE.
 *
 * This file has no DOM dependencies and can be tested independently.
 */

/* exported CodeGen */
const CodeGen = (() => {
    "use strict";

    // ── URL helpers ──────────────────────────────────────────────────────

    /**
     * Parse a Microsoft API URL (Graph or Defender XDR portal proxy) into its
     * constituent parts.
     *
     * Handles two URL shapes:
     *  1. Direct Graph API:
     *       https://graph.microsoft.com/{version}/{resource}
     *  2. Defender XDR portal proxy (MTP):
     *       https://security.microsoft.com/apiproxy/{proxy}/{service}/{resource}
     *     The {service} segment is an internal portal service name; it is stripped
     *     to derive the equivalent Microsoft 365 Defender REST API path at
     *     https://api.security.microsoft.com/api/{resource}.
     *
     * @param {string} rawUrl
     * @returns {{
     *   version: string,          // "v1.0" | "beta"
     *   resourcePath: string,     // "/{resource}" without version/proxy prefix
     *   fullPath: string,         // full pathname as captured
     *   isProxy: boolean,         // true for security.microsoft.com/apiproxy/* URLs
     *   publicApiPath: string,    // "/v1.0/…" for Graph, "/api/…" for proxy
     *   params: Record<string, string>,
     *   hasParams: boolean,
     *   queryString: string,      // e.g. "?$filter=…"
     * }}
     */
    function parseGraphUrl(rawUrl) {
        let urlObj;
        try {
            urlObj = new URL(rawUrl);
        } catch {
            return {
                version: "v1.0",
                resourcePath: rawUrl,
                fullPath: rawUrl,
                isProxy: false,
                publicApiPath: rawUrl,
                params: {},
                hasParams: false,
                queryString: "",
            };
        }

        /** @type {Record<string, string>} */
        const params = {};
        urlObj.searchParams.forEach((v, k) => { params[k] = v; });
        const hasParams = urlObj.searchParams.size > 0;

        // ── Defender XDR portal proxy calls ──────────────────────────────────
        // Path shape:  /apiproxy/{proxy}/{service}/{resource…}
        // e.g.:        /apiproxy/mtp/incidentUpdate/incidents/123
        // The {service} segment is an internal portal name; strip it together with
        // the /apiproxy/{proxy}/ prefix to derive the public resource path.
        if (urlObj.hostname === "security.microsoft.com" &&
                urlObj.pathname.startsWith("/apiproxy/")) {
            const segments = urlObj.pathname.split("/").filter(Boolean);
            // segments: ["apiproxy", "{proxy}", "{service}", "{resource}", …]
            const resourcePath = "/" + segments.slice(3).join("/");
            return {
                version: "v1.0",
                resourcePath,
                fullPath: urlObj.pathname,
                isProxy: true,
                publicApiPath: "/api" + resourcePath,
                params,
                hasParams,
                queryString: urlObj.search,
            };
        }

        // ── Direct Graph API call ─────────────────────────────────────────────
        // Path shape:  /{version}/{resource…}
        // e.g.:        /v1.0/security/incidents
        const segments = urlObj.pathname.split("/").filter(Boolean);
        const version = segments[0] || "v1.0";
        const resourcePath = "/" + segments.slice(1).join("/");
        return {
            version,
            resourcePath,
            fullPath: urlObj.pathname,
            isProxy: false,
            publicApiPath: urlObj.pathname,
            params,
            hasParams,
            queryString: urlObj.search,
        };
    }

    // ── String-escaping helpers ──────────────────────────────────────────

    /**
     * Escape a string for embedding inside a PowerShell double-quoted string.
     * Escapes backticks, double-quotes, and dollar signs.
     * @param {string} s
     * @returns {string}
     */
    function escapePsDoubleQuoted(s) {
        return s
            .replace(/`/g, "``")       // backtick → ``
            .replace(/"/g, '`"')       // " → `"
            .replace(/\$/g, "`$");     // $ → `$  (prevents variable expansion)
    }

    /**
     * Escape a string for embedding inside a Python double-quoted string.
     * @param {string} s
     * @returns {string}
     */
    function escapePyString(s) {
        return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
    }

    /**
     * Escape a string for embedding inside a C# verbatim (@"…") string.
     * In verbatim strings only the double-quote needs doubling.
     * @param {string} s
     * @returns {string}
     */
    function escapeCsVerbatim(s) {
        return s.replace(/"/g, '""');
    }

    /**
     * Escape a string for embedding inside a JavaScript template literal.
     * @param {string} s
     * @returns {string}
     */
    function escapeJsTemplate(s) {
        return s.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$\{/g, "\\${");
    }

    // ── Body helpers ─────────────────────────────────────────────────────

    /**
     * Try to pretty-print a JSON string; return the original string on failure.
     * @param {string|null|undefined} raw
     * @returns {string}
     */
    function prettyJson(raw) {
        if (!raw) return "";
        try {
            return JSON.stringify(JSON.parse(raw), null, 4);
        } catch {
            return raw;
        }
    }

    // ── Language generators ──────────────────────────────────────────────

    /**
     * Generate a PowerShell script.
     *
     * Direct Graph API calls use Connect-MgGraph + Invoke-MgGraphRequest.
     * Portal proxy calls use MSAL.PS token acquisition + Invoke-RestMethod
     * against the equivalent Microsoft 365 Defender REST API.
     *
     * @param {import('./panel.js').RequestEntry} req
     * @returns {string}
     */
    function generatePowerShell(req) {
        const { method, url, requestBody, isProxy, publicApiUrl } = req;
        const targetUrl = isProxy && publicApiUrl ? publicApiUrl : url;
        const uri = escapePsDoubleQuoted(targetUrl);
        const hasBody = !!requestBody && method !== "GET";

        const lines = [
            "# Generated by Defender XRay",
            `# ${method} ${url}`,
            "#",
        ];

        if (isProxy) {
            lines.push(
                "# NOTE: Captured as a Defender XDR portal proxy call.",
                "# The script below targets the equivalent Microsoft 365 Defender REST API.",
                "# Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-supported",
                "#",
                "# Prerequisites",
                "#   Install-Module MSAL.PS -Scope CurrentUser",
                "",
                "# Acquire a token for the Microsoft 365 Defender REST API.",
                "Import-Module MSAL.PS",
                "",
                '$tokenResponse = Get-MsalToken `',
                '    -TenantId "YOUR_TENANT_ID" `',
                '    -ClientId "YOUR_CLIENT_ID" `',
                '    -ClientSecret (ConvertTo-SecureString "YOUR_CLIENT_SECRET" -AsPlainText -Force) `',
                '    -Scopes "https://api.security.microsoft.com/.default"',
                "",
                "$headers = @{",
                '    Authorization = "Bearer $($tokenResponse.AccessToken)"',
                '    "Content-Type" = "application/json"',
                "}",
                "",
            );
        } else {
            lines.push(
                "# Prerequisites",
                "#   Install-Module Microsoft.Graph -Scope CurrentUser",
                "",
                "# Connect to Microsoft Graph (interactive, browser-based login).",
                "# For unattended/app-only auth use:",
                "#   Connect-MgGraph -TenantId <tenant-id> -ClientId <app-id> -CertificateThumbprint <thumb>",
                "Connect-MgGraph",
                "",
            );
        }

        if (hasBody) {
            lines.push("# Request body");
            lines.push(`$body = '${prettyJson(requestBody).replace(/'/g, "''")}'`);
            lines.push("");
        }

        lines.push(`# ${method} ${req.path || url}`);

        if (isProxy) {
            lines.push(`$response = Invoke-RestMethod \``);
            lines.push(`    -Method ${method} \``);
            lines.push(`    -Uri "${uri}" \``);
            lines.push(`    -Headers $headers \``);
            if (hasBody) {
                lines.push(`    -Body $body \``);
            }
            lines.push(`    -ErrorAction Stop`);
        } else {
            lines.push(`$response = Invoke-MgGraphRequest \``);
            lines.push(`    -Method ${method} \``);
            lines.push(`    -Uri "${uri}" \``);
            if (hasBody) {
                lines.push(`    -Body $body \``);
                lines.push(`    -ContentType "application/json" \``);
            }
            lines.push(`    -OutputType PSObject`);
        }

        lines.push("");
        lines.push("# Display the response");
        lines.push("$response | ConvertTo-Json -Depth 10");

        return lines.join("\n");
    }

    /**
     * Generate a Python script using the `requests` library and MSAL for auth.
     * The auth scope adjusts automatically for Graph vs MTP API calls.
     *
     * @param {import('./panel.js').RequestEntry} req
     * @returns {string}
     */
    function generatePython(req) {
        const { method, url, requestBody, isProxy, publicApiUrl } = req;
        const targetUrl = isProxy && publicApiUrl ? publicApiUrl : url;
        const parsed = parseGraphUrl(url);
        const hasBody = !!requestBody && method !== "GET";

        const authScope = isProxy
            ? "https://api.security.microsoft.com/.default"
            : "https://graph.microsoft.com/.default";

        // Split query params into a separate dict for readability
        const baseUrl = targetUrl.split("?")[0];
        const paramEntries = Object.entries(parsed.params);

        const lines = [
            "# Generated by Defender XRay",
            `# ${method} ${url}`,
            "#",
        ];

        if (isProxy) {
            lines.push(
                "# NOTE: Captured as a Defender XDR portal proxy call.",
                "# The script below targets the equivalent Microsoft 365 Defender REST API.",
                "# Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-supported",
                "#",
            );
        }

        lines.push(
            "# Prerequisites",
            "#   pip install requests msal",
            "",
            "import requests",
            "import msal",
            "",
            "# ── Authentication ──────────────────────────────────────────",
            "# Replace the placeholders below with your app registration details.",
            '# Create an app at https://entra.microsoft.com > App registrations.',
            'TENANT_ID     = "YOUR_TENANT_ID"',
            'CLIENT_ID     = "YOUR_CLIENT_ID"',
            'CLIENT_SECRET = "YOUR_CLIENT_SECRET"   # Use a certificate in production',
            "",
            "app = msal.ConfidentialClientApplication(",
            "    CLIENT_ID,",
            '    authority=f"https://login.microsoftonline.com/{TENANT_ID}",',
            "    client_credential=CLIENT_SECRET,",
            ")",
            "",
            "token_response = app.acquire_token_for_client(",
            `    scopes=["${authScope}"]`,
            ")",
            'if "access_token" not in token_response:',
            '    raise RuntimeError(f"Could not acquire token: {token_response}")',
            "",
            "headers = {",
            '    "Authorization": f"Bearer {token_response[\'access_token\']}",',
            '    "Content-Type": "application/json",',
            "}",
            "",
            "# ── API call ─────────────────────────────────────────────────",
        );

        if (paramEntries.length > 0) {
            lines.push(`url = "${escapePyString(baseUrl)}"`);
            lines.push("params = {");
            for (const [k, v] of paramEntries) {
                lines.push(`    "${escapePyString(k)}": "${escapePyString(v)}",`);
            }
            lines.push("}");
        } else {
            lines.push(`url = "${escapePyString(targetUrl)}"`);
        }

        if (hasBody) {
            lines.push("");
            lines.push("body = (");
            // Indent body JSON by 4 spaces
            const bodyStr = prettyJson(requestBody);
            for (const line of bodyStr.split("\n")) {
                lines.push(`    ${line}`);
            }
            lines.push(")");
        }

        lines.push("");
        const pyMethod = method.toLowerCase();
        const callArgs = paramEntries.length > 0 ? "url, headers=headers, params=params" : "url, headers=headers";

        if (hasBody) {
            lines.push(`response = requests.${pyMethod}(`);
            lines.push(`    ${callArgs.replace("url, ", "url,\n    ")},`);
            lines.push("    json=body,");
            lines.push(")");
        } else {
            lines.push(`response = requests.${pyMethod}(${callArgs})`);
        }

        lines.push("");
        lines.push("response.raise_for_status()");
        lines.push("print(response.json())");

        return lines.join("\n");
    }

    /**
     * Generate a C# script using HttpClient and Azure.Identity for auth.
     * Targets .NET 8 with top-level statements for brevity.
     * The auth scope adjusts automatically for Graph vs MTP API calls.
     *
     * @param {import('./panel.js').RequestEntry} req
     * @returns {string}
     */
    function generateCSharp(req) {
        const { method, url, requestBody, isProxy, publicApiUrl } = req;
        const targetUrl = isProxy && publicApiUrl ? publicApiUrl : url;
        const hasBody = !!requestBody && method !== "GET";
        const csMethod = method === "PATCH" ? "Patch" : _capitalize(method.toLowerCase());

        const authScope = isProxy
            ? "https://api.security.microsoft.com/.default"
            : "https://graph.microsoft.com/.default";

        const lines = [
            "// Generated by Defender XRay",
            `// ${method} ${url}`,
            "//",
        ];

        if (isProxy) {
            lines.push(
                "// NOTE: Captured as a Defender XDR portal proxy call.",
                "// The script below targets the equivalent Microsoft 365 Defender REST API.",
                "// Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-supported",
                "//",
            );
        }

        lines.push(
            "// Prerequisites (NuGet packages)",
            "//   dotnet add package Azure.Identity",
            "//   dotnet add package System.Net.Http.Json",
            "",
            "using Azure.Core;",
            "using Azure.Identity;",
            "using System.Net.Http;",
            "using System.Net.Http.Headers;",
            "using System.Net.Http.Json;",
            "using System.Text;",
            "using System.Text.Json;",
            "",
            "// ── Authentication ──────────────────────────────────────────",
            "// Replace the placeholders below with your app registration details.",
            "// Create an app at https://entra.microsoft.com > App registrations.",
            'var tenantId     = "YOUR_TENANT_ID";',
            'var clientId     = "YOUR_CLIENT_ID";',
            'var clientSecret = "YOUR_CLIENT_SECRET"; // Use a certificate in production',
            "",
            "var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);",
            "var tokenRequest = new TokenRequestContext(",
            `    new[] { "${authScope}" }`,
            ");",
            "var token = await credential.GetTokenAsync(tokenRequest);",
            "",
            "using var httpClient = new HttpClient();",
            "httpClient.DefaultRequestHeaders.Authorization =",
            '    new AuthenticationHeaderValue("Bearer", token.Token);',
            "",
            "// ── API call ─────────────────────────────────────────────────",
            `var url = @"${escapeCsVerbatim(targetUrl)}";`,
            "",
        );

        if (hasBody) {
            const bodyStr = prettyJson(requestBody);
            lines.push(`var requestBody = @"${escapeCsVerbatim(bodyStr)}";`);
            lines.push(`var content = new StringContent(requestBody, Encoding.UTF8, "application/json");`);
            lines.push("");

            if (method === "POST") {
                lines.push("var response = await httpClient.PostAsync(url, content);");
            } else if (method === "PUT") {
                lines.push("var response = await httpClient.PutAsync(url, content);");
            } else if (method === "PATCH") {
                lines.push("var request = new HttpRequestMessage(HttpMethod.Patch, url) { Content = content };");
                lines.push("var response = await httpClient.SendAsync(request);");
            } else {
                lines.push(`var response = await httpClient.${csMethod}Async(url, content);`);
            }
        } else if (method === "DELETE") {
            lines.push("var response = await httpClient.DeleteAsync(url);");
        } else {
            lines.push("var response = await httpClient.GetAsync(url);");
        }

        lines.push("response.EnsureSuccessStatusCode();");
        lines.push("");
        lines.push("var responseBody = await response.Content.ReadAsStringAsync();");
        lines.push("var formatted = JsonSerializer.Serialize(");
        lines.push("    JsonSerializer.Deserialize<JsonElement>(responseBody),");
        lines.push("    new JsonSerializerOptions { WriteIndented = true }");
        lines.push(");");
        lines.push("Console.WriteLine(formatted);");

        return lines.join("\n");
    }

    /**
     * Generate a JavaScript script.
     *
     * Direct Graph API calls use the Microsoft Graph JavaScript SDK.
     * Portal proxy calls use the fetch API against the equivalent Microsoft 365
     * Defender REST API, since the Graph SDK only targets graph.microsoft.com.
     *
     * @param {import('./panel.js').RequestEntry} req
     * @returns {string}
     */
    function generateJavaScript(req) {
        const { method, url, requestBody, isProxy, publicApiUrl } = req;
        const targetUrl = isProxy && publicApiUrl ? publicApiUrl : url;
        const parsed = parseGraphUrl(url);
        const hasBody = !!requestBody && method !== "GET";

        const lines = [
            "// Generated by Defender XRay",
            `// ${method} ${url}`,
            "//",
        ];

        if (isProxy) {
            // ── Portal proxy: use fetch + Azure.Identity directly ─────────────
            lines.push(
                "// NOTE: Captured as a Defender XDR portal proxy call.",
                "// The script below targets the equivalent Microsoft 365 Defender REST API.",
                "// Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-supported",
                "//",
                "// Prerequisites (npm packages)",
                "//   npm install @azure/identity",
                "",
                'import { ClientSecretCredential } from "@azure/identity";',
                "",
                "// ── Authentication ──────────────────────────────────────────",
                "// Replace the placeholders below with your app registration details.",
                "// Create an app at https://entra.microsoft.com > App registrations.",
                'const tenantId     = "YOUR_TENANT_ID";',
                'const clientId     = "YOUR_CLIENT_ID";',
                'const clientSecret = "YOUR_CLIENT_SECRET"; // Use a certificate in production',
                "",
                "const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);",
                "const { token } = await credential.getToken(",
                '    "https://api.security.microsoft.com/.default"',
                ");",
                "",
                "// ── API call ─────────────────────────────────────────────────",
            );

            if (hasBody) {
                lines.push("const body = " + prettyJson(requestBody) + ";");
                lines.push("");
            }

            lines.push(`const response = await fetch("${escapeJsTemplate(targetUrl)}", {`);
            lines.push(`    method: "${method}",`);
            lines.push("    headers: {");
            lines.push("        \"Authorization\": `Bearer ${token}`,");
            lines.push('        "Content-Type": "application/json",');
            lines.push("    },");
            if (hasBody) {
                lines.push("    body: JSON.stringify(body),");
            }
            lines.push("});");
            lines.push("");
            lines.push("if (!response.ok) {");
            lines.push("    throw new Error(`Request failed: ${response.status} ${response.statusText}`);");
            lines.push("}");
            lines.push("const result = await response.json();");
            lines.push("console.log(JSON.stringify(result, null, 2));");
        } else {
            // ── Direct Graph API: use the Graph JavaScript SDK ────────────────
            // The Graph JS SDK's .api() accepts the path relative to graph.microsoft.com
            const apiPath = escapeJsTemplate(parsed.fullPath + parsed.queryString);

            lines.push(
                "// Prerequisites (npm packages)",
                "//   npm install @microsoft/microsoft-graph-client",
                "//   npm install @azure/identity",
                "//   npm install @microsoft/microsoft-graph-client/authProviders/azureTokenCredentials",
                "",
                'import { Client } from "@microsoft/microsoft-graph-client";',
                'import { ClientSecretCredential } from "@azure/identity";',
                'import { TokenCredentialAuthenticationProvider }',
                '    from "@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials";',
                "",
                "// ── Authentication ──────────────────────────────────────────",
                "// Replace the placeholders below with your app registration details.",
                "// Create an app at https://entra.microsoft.com > App registrations.",
                'const tenantId     = "YOUR_TENANT_ID";',
                'const clientId     = "YOUR_CLIENT_ID";',
                'const clientSecret = "YOUR_CLIENT_SECRET"; // Use a certificate in production',
                "",
                "const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);",
                "const authProvider = new TokenCredentialAuthenticationProvider(credential, {",
                '    scopes: ["https://graph.microsoft.com/.default"],',
                "});",
                "const client = Client.initWithMiddleware({ authProvider });",
                "",
                "// ── API call ─────────────────────────────────────────────────",
            );

            if (hasBody) {
                lines.push("const body = " + prettyJson(requestBody) + ";");
                lines.push("");
            }

            const jsMethod = method.toLowerCase();

            if (hasBody) {
                lines.push(`const result = await client.api(\`${apiPath}\`).${jsMethod}(body);`);
            } else if (method === "DELETE") {
                lines.push(`await client.api(\`${apiPath}\`).delete();`);
                lines.push("console.log('Deleted successfully');");
                return lines.join("\n");
            } else {
                lines.push(`const result = await client.api(\`${apiPath}\`).get();`);
            }

            lines.push("console.log(JSON.stringify(result, null, 2));");
        }

        return lines.join("\n");
    }

    // ── Private utilities ────────────────────────────────────────────────

    /** Capitalise the first character of a string. */
    function _capitalize(s) {
        return s.charAt(0).toUpperCase() + s.slice(1);
    }

    // ── Public API ───────────────────────────────────────────────────────

    /**
     * Generate a code snippet for the given request and language.
     *
     * @param {import('./panel.js').RequestEntry} req
     * @param {"powershell"|"python"|"csharp"|"javascript"} language
     * @returns {string} The generated code snippet as a plain string.
     */
    function generate(req, language) {
        switch (language) {
            case "powershell":  return generatePowerShell(req);
            case "python":      return generatePython(req);
            case "csharp":      return generateCSharp(req);
            case "javascript":  return generateJavaScript(req);
            default:            return `// Unsupported language: ${language}`;
        }
    }

    return {
        generate,
        parseGraphUrl,   // Exposed for unit tests
    };
})();
