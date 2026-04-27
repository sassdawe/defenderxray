/**
 * panel.js
 *
 * Main application logic for the Defender XRay DevTools panel.
 *
 * Responsibilities
 * ────────────────
 * • Listen for network requests via chrome.devtools.network.onRequestFinished
 * • Filter for Microsoft Graph API calls (graph.microsoft.com)
 * • Render each captured call as a row in the request table
 * • Show full request/response details when a row is selected
 * • Delegate code-snippet generation to codegen.js (CodeGen.generate)
 * • Export all captured requests to a JSON file
 * • Provide a draggable split pane between the list and details panels
 *
 * @typedef {{
 *   id:              number,
 *   method:          string,
 *   url:             string,
 *   path:            string,
 *   version:         string,
 *   isProxy:         boolean,
 *   publicApiUrl:    string|null,
 *   status:          number,
 *   statusText:      string,
 *   durationMs:      number,
 *   startedDateTime: string,
 *   requestHeaders:  Array<{name: string, value: string}>,
 *   requestBody:     string|null,
 *   responseHeaders: Array<{name: string, value: string}>,
 *   responseBody:    string|null,
 * }} RequestEntry
 */

(function () {
    "use strict";

    // ── State ────────────────────────────────────────────────────────────

    /** @type {RequestEntry[]} */
    const captured = [];

    /** @type {RequestEntry|null} */
    let selected = null;

    /** Whether the extension is actively recording new requests. */
    let isRecording = true;

    if (!globalThis.Redaction) {
        throw new Error("Redaction module missing. Ensure redaction.js loads before panel.js.");
    }

    const {
        sanitizeRequestEntry,
        sanitizeHeaderValue,
        redactSensitiveQueryParams,
    } = globalThis.Redaction;

    // ── DOM references ───────────────────────────────────────────────────

    const btnCapture      = document.getElementById("btn-capture");
    const captureLabel    = document.getElementById("capture-label");
    const btnClear        = document.getElementById("btn-clear");
    const btnExport       = document.getElementById("btn-export");
    const btnExportLimited = document.getElementById("btn-export-limited");
    const requestCount    = document.getElementById("request-count");

    const emptyState      = document.getElementById("empty-state");
    const requestTable    = document.getElementById("request-table");
    const requestTbody    = document.getElementById("request-tbody");

    const detailsPlaceholder = document.getElementById("details-placeholder");
    const detailsContent     = document.getElementById("details-content");

    // Overview fields
    const ovUrl      = document.getElementById("ov-url");
    const ovMethod   = document.getElementById("ov-method");
    const ovStatus   = document.getElementById("ov-status");
    const ovTime     = document.getElementById("ov-time");
    const ovVersion  = document.getElementById("ov-version");
    const ovStarted  = document.getElementById("ov-started");

    // Request tab
    const reqHeaders = document.getElementById("req-headers");
    const reqBody    = document.getElementById("req-body");

    // Response tab
    const resHeaders = document.getElementById("res-headers");
    const resBody    = document.getElementById("res-body");

    // Code tab
    const languageSelect = document.getElementById("language-select");
    const btnCopy        = document.getElementById("btn-copy");
    const codeContent    = document.getElementById("code-content");

    // Resizer
    const resizer         = document.getElementById("resizer");
    const requestListPane = document.getElementById("request-list-pane");

    // ── Network listener ─────────────────────────────────────────────────

    /**
     * Called by Chrome DevTools for every completed network request while the
     * DevTools panel is open.  We filter for Graph API requests only.
     *
     * @param {chrome.devtools.network.Request} entry – HAR-format entry
     */
    chrome.devtools.network.onRequestFinished.addListener(function (entry) {
        if (!isRecording) return;

        const url = entry.request.url;

        // Filter by exact hostname to avoid substring-match bypasses.
        // Capture two origins:
        //   • graph.microsoft.com              — direct Microsoft Graph API calls
        //   • security.microsoft.com/apiproxy/ — Defender XDR portal proxy to MTP API
        let urlObj;
        try {
            urlObj = new URL(url);
        } catch {
            return; // Ignore malformed URLs
        }
        const { hostname, pathname } = urlObj;
        const isGraphApi  = hostname === "graph.microsoft.com";
        const isProxyCall = hostname === "security.microsoft.com" &&
                            pathname.startsWith("/apiproxy/");
        if (!isGraphApi && !isProxyCall) return;

        const method = entry.request.method.toUpperCase();
        if (!["GET", "POST", "PATCH", "PUT", "DELETE"].includes(method)) return;

        // getContent is async; it delivers the response body via callback.
        entry.getContent(function (responseBody, _encoding) {
            const parsed = CodeGen.parseGraphUrl(url);

            // For portal proxy calls, resolve the path against the known API
            // mapping.  Skip calls that have no public API equivalent (portal-
            // internal endpoints).
            let publicApiUrl = null;
            if (parsed.isProxy) {
                const resolved = CodeGen.resolveProxyUrl(parsed.fullPath);
                if (!resolved) return; // unmapped / portal-internal — ignore
                // Append the original query string only when the resolved URL
                // doesn't already carry its own (e.g. the Sentinel ARM URL).
                publicApiUrl = resolved.includes("?")
                    ? resolved
                    : resolved + parsed.queryString;
            }

            /** @type {RequestEntry} */
            const req = {
                id:              captured.length + 1,
                method,
                url,
                path:            parsed.fullPath + parsed.queryString,
                version:         parsed.version,
                isProxy:         parsed.isProxy,
                publicApiUrl,
                status:          entry.response.status,
                statusText:      entry.response.statusText,
                durationMs:      Math.round(entry.time),
                startedDateTime: entry.startedDateTime,
                requestHeaders:  entry.request.headers,
                requestBody:     entry.request.postData ? entry.request.postData.text : null,
                responseHeaders: entry.response.headers,
                responseBody:    responseBody || null,
            };

            captured.push(req);
            addRow(req);
            updateCount();
        });
    });

    // ── Toolbar button handlers ──────────────────────────────────────────

    btnCapture.addEventListener("click", function () {
        isRecording = !isRecording;
        btnCapture.classList.toggle("active", isRecording);
        captureLabel.textContent = isRecording ? "Recording" : "Paused";
        btnCapture.title = isRecording ? "Pause capture" : "Resume capture";
    });

    btnClear.addEventListener("click", function () {
        captured.length = 0;
        selected = null;
        requestTbody.innerHTML = "";
        showEmptyState(true);
        showDetails(false);
        updateCount();
    });

    btnExport.addEventListener("click", exportToJson);
    btnExportLimited.addEventListener("click", exportToJsonLimited);

    // ── Request table ────────────────────────────────────────────────────

    /**
     * Append a new row to the request table for the given entry.
     * @param {RequestEntry} req
     */
    function addRow(req) {
        // Show table, hide empty state
        showEmptyState(false);

        const tr = document.createElement("tr");
        tr.className = "request-row";
        tr.dataset.id = String(req.id);

        // Method badge
        const tdMethod = document.createElement("td");
        tdMethod.className = "col-method";
        tdMethod.innerHTML = `<span class="method-badge method-${req.method}">${escHtml(req.method)}</span>`;

        // Path (resource path, truncated visually via CSS)
        const tdPath = document.createElement("td");
        tdPath.className = "col-path";
        tdPath.title = req.url;               // full URL on hover
        tdPath.textContent = req.path || req.url;

        // Status
        const tdStatus = document.createElement("td");
        tdStatus.className = "col-status";
        const statusClass = statusCssClass(req.status);
        tdStatus.innerHTML = `<span class="${statusClass}">${req.status}</span>`;

        // Duration
        const tdTime = document.createElement("td");
        tdTime.className = "col-time";
        tdTime.textContent = req.durationMs >= 0 ? String(req.durationMs) : "–";

        tr.append(tdMethod, tdPath, tdStatus, tdTime);

        tr.addEventListener("click", function () {
            selectRow(req, tr);
        });

        requestTbody.appendChild(tr);

        // If the new row belongs to the active selection (shouldn't normally
        // happen but guards against race conditions), refresh the details pane.
        if (selected && selected.id === req.id) {
            renderDetails(req);
        }
    }

    /**
     * Mark a row as selected and render its details.
     * @param {RequestEntry} req
     * @param {HTMLTableRowElement} tr
     */
    function selectRow(req, tr) {
        // Deselect previous
        const prev = requestTbody.querySelector(".selected");
        if (prev) prev.classList.remove("selected");

        tr.classList.add("selected");
        selected = req;
        renderDetails(req);
    }

    // ── Details pane ─────────────────────────────────────────────────────

    /**
     * Populate every details tab with data from `req` and show the pane.
     * @param {RequestEntry} req
     */
    function renderDetails(req) {
        showDetails(true);

        // Overview
        ovUrl.textContent     = req.url;
        ovMethod.innerHTML    = `<span class="method-badge method-${req.method}">${escHtml(req.method)}</span>`;
        ovStatus.innerHTML    = `<span class="${statusCssClass(req.status)}">${req.status} ${escHtml(req.statusText)}</span>`;
        ovTime.textContent    = req.durationMs >= 0 ? `${req.durationMs} ms` : "–";
        ovVersion.textContent = req.isProxy ? "MTP API (portal proxy)" : req.version;
        ovStarted.textContent = req.startedDateTime ? formatDateTime(req.startedDateTime) : "–";

        // Use one sanitizer policy for UI detail panes and exports.
        const sanitized = sanitizeRequestEntry(req);

        // Request tab
        reqHeaders.querySelector("code").textContent = formatHeaders(sanitized.requestHeaders);
        reqBody.querySelector("code").textContent    = sanitized.requestBody ? prettyJson(sanitized.requestBody) : "(no body)";

        // Response tab
        resHeaders.querySelector("code").textContent = formatHeaders(sanitized.responseHeaders);
        resBody.querySelector("code").textContent    = sanitized.responseBody ? prettyJson(sanitized.responseBody) : "(no body)";

        // Code tab – regenerate with the currently selected language
        refreshCode(req);
    }

    // ── Tab switching ─────────────────────────────────────────────────────

    document.getElementById("tab-bar").addEventListener("click", function (e) {
        const btn = e.target.closest(".tab");
        if (!btn) return;

        const tabName = btn.dataset.tab;

        // Update button states
        document.querySelectorAll(".tab").forEach(function (t) {
            const active = t.dataset.tab === tabName;
            t.classList.toggle("active", active);
            t.setAttribute("aria-selected", String(active));
        });

        // Update panel visibility
        document.querySelectorAll(".tab-content").forEach(function (panel) {
            const active = panel.id === `tab-${tabName}`;
            panel.classList.toggle("active", active);
            panel.hidden = !active;
        });
    });

    // ── Code generation ───────────────────────────────────────────────────

    languageSelect.addEventListener("change", function () {
        if (selected) refreshCode(selected);
    });

    /**
     * Re-render the code snippet for the given request + current language.
     * @param {RequestEntry} req
     */
    function refreshCode(req) {
        const lang = languageSelect.value;
        codeContent.textContent = CodeGen.generate(req, lang);
    }

    /** Copy the currently displayed code to the clipboard. */
    btnCopy.addEventListener("click", function () {
        const text = codeContent.textContent;
        if (!text) return;

        navigator.clipboard.writeText(text).then(function () {
            btnCopy.textContent = "Copied!";
            btnCopy.classList.add("copied");
            setTimeout(function () {
                btnCopy.textContent = "Copy";
                btnCopy.classList.remove("copied");
            }, 1500);
        }).catch(function () {
            // Fallback for environments where clipboard API is not available
            const ta = document.createElement("textarea");
            ta.value = text;
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            document.body.removeChild(ta);
            btnCopy.textContent = "Copied!";
            setTimeout(function () { btnCopy.textContent = "Copy"; }, 1500);
        });
    });

    // ── Export ────────────────────────────────────────────────────────────

    /** Download all captured requests as a JSON file. */
    function exportToJson() {
        if (captured.length === 0) return;

        const safeCaptured = captured.map(sanitizeRequestEntry);
        const data = JSON.stringify(safeCaptured, null, 2);
        const blob = new Blob([data], { type: "application/json" });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");

        a.href     = url;
        a.download = `defender-xray-${timestamp()}.json`;
        a.click();

        URL.revokeObjectURL(url);
    }

    /**
     * Download a limited subset of captured requests as a JSON file.
     * Only includes: method, url, path, version, isProxy, publicApiUrl,
     * status, statusText — useful for researching API usage and building
     * an API translation layer.
     */
    function exportToJsonLimited() {
        if (captured.length === 0) return;

        const limited = captured.map(function (req) {
            return {
                method:       req.method,
                url:          redactSensitiveQueryParams(req.url),
                path:         redactSensitiveQueryParams(req.path),
                version:      req.version,
                isProxy:      req.isProxy,
                publicApiUrl: req.publicApiUrl ? redactSensitiveQueryParams(req.publicApiUrl) : null,
                status:       req.status,
                statusText:   req.statusText,
            };
        });

        const data = JSON.stringify(limited, null, 2);
        const blob = new Blob([data], { type: "application/json" });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");

        a.href     = url;
        a.download = `defender-xray-limited-${timestamp()}.json`;
        a.click();

        URL.revokeObjectURL(url);
    }

    // ── Draggable resizer ─────────────────────────────────────────────────

    (function initResizer() {
        let dragging = false;
        let startX   = 0;
        let startW   = 0;

        resizer.addEventListener("mousedown", function (e) {
            dragging = true;
            startX   = e.clientX;
            startW   = requestListPane.getBoundingClientRect().width;
            resizer.classList.add("dragging");
            document.body.style.cursor = "col-resize";
            document.body.style.userSelect = "none";
        });

        document.addEventListener("mousemove", function (e) {
            if (!dragging) return;
            const delta  = e.clientX - startX;
            const newW   = Math.max(160, Math.min(startW + delta, window.innerWidth - 240));
            requestListPane.style.width = `${newW}px`;
        });

        document.addEventListener("mouseup", function () {
            if (!dragging) return;
            dragging = false;
            resizer.classList.remove("dragging");
            document.body.style.cursor = "";
            document.body.style.userSelect = "";
        });

        // Keyboard accessibility: arrow keys move the divider
        resizer.addEventListener("keydown", function (e) {
            const step = e.shiftKey ? 20 : 5;
            const cur  = requestListPane.getBoundingClientRect().width;
            if (e.key === "ArrowLeft")  requestListPane.style.width = `${Math.max(160, cur - step)}px`;
            if (e.key === "ArrowRight") requestListPane.style.width = `${Math.min(window.innerWidth - 240, cur + step)}px`;
        });
    }());

    // ── Helpers ───────────────────────────────────────────────────────────

    /** Show or hide the empty state / request table. */
    function showEmptyState(empty) {
        emptyState.hidden    = !empty;
        requestTable.hidden  = empty;
    }

    /** Show or hide the details pane content vs placeholder. */
    function showDetails(show) {
        detailsPlaceholder.hidden = show;
        detailsContent.hidden     = !show;
    }

    /** Update the request count badge in the toolbar. */
    function updateCount() {
        const n = captured.length;
        requestCount.textContent = n === 1 ? "1 request" : `${n} requests`;
    }

    /**
     * Format an array of HAR header objects into a readable string.
     * Redacts Authorization tokens for display safety.
     * @param {Array<{name: string, value: string}>} headers
     * @returns {string}
     */
    function formatHeaders(headers) {
        if (!headers || headers.length === 0) return "(none)";
        return headers
            .map(function (h) {
                const value = sanitizeHeaderValue(h.name, h.value);
                return `${h.name}: ${value}`;
            })
            .join("\n");
    }

    /**
     * Try to pretty-print a JSON string; return as-is on parse failure.
     * @param {string} raw
     * @returns {string}
     */
    function prettyJson(raw) {
        if (!raw) return "";
        try {
            return JSON.stringify(JSON.parse(raw), null, 2);
        } catch {
            return raw;
        }
    }

    /**
     * Return a CSS class for a given HTTP status code.
     * @param {number} status
     * @returns {string}
     */
    function statusCssClass(status) {
        if (status >= 500) return "status-5xx";
        if (status >= 400) return "status-4xx";
        if (status >= 300) return "status-3xx";
        if (status >= 200) return "status-2xx";
        return "";
    }

    /**
     * Escape special HTML characters to prevent XSS when injecting text via innerHTML.
     * @param {string} s
     * @returns {string}
     */
    function escHtml(s) {
        return String(s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    /**
     * Format an ISO 8601 datetime string into a human-readable local time.
     * @param {string} iso
     * @returns {string}
     */
    function formatDateTime(iso) {
        try {
            return new Date(iso).toLocaleString();
        } catch {
            return iso;
        }
    }

    /** Return a compact timestamp string for use in export filenames. */
    function timestamp() {
        return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    }

    // ── Initialisation ────────────────────────────────────────────────────

    showEmptyState(true);
    showDetails(false);
    updateCount();

}());
