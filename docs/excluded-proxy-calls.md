# Excluded Portal Proxy Calls

The Defender XDR portal routes all its internal API traffic through
`https://security.microsoft.com/apiproxy/…`.  Of the proxy paths observed
in the wild, only a subset have a documented public Microsoft API equivalent
(see [`research/api-mapping.json`](../research/api-mapping.json)).  The
Defender XRay extension silently ignores all proxy calls that do **not** map
to a public API, because they serve portal-internal UI concerns and cannot be
replicated with a user-issued API call.

The table below documents the 32 excluded paths and the reason each one is
excluded.

| Proxy path pattern | Reason excluded |
|--------------------|-----------------|
| `^/apiproxy/cdssecuritycopilot/trial$` | Internal Security Copilot (Medeina) licensing/trial check. The required OAuth scope (`https://api.medeina.defender.microsoft.com/Medeina.Access`) is a private API surface. No public Microsoft API equivalent. |
| `^/apiproxy/mtoapi/tenants/TenantPicker$` | Portal-internal multi-tenant UX picker used to switch between managed tenants. No public Microsoft API equivalent. |
| `^/apiproxy/mtp/alertsApiService/alerts/count$` | Portal-internal alert count aggregation used to populate queue badge counts. No public Microsoft API equivalent. |
| `^/apiproxy/mtp/alertsApiService/alerts/[^/]+/context$` | Portal-internal alert enrichment endpoint (resolves related processes, files, and network connections displayed in the Defender XDR alert page). No public Microsoft API equivalent. |
| `^/apiproxy/mtp/alertsApiService/alerts/[^/]+/similarAlertsSummary$` | Portal-internal ML-generated similar-alerts summary card. No public Microsoft API equivalent. |
| `^/apiproxy/mtp/auditHistory/AuditHistory` | Portal-internal incident/entity audit log (tracks status changes, assignment changes, and comments). No public Microsoft API equivalent. |
| `^/apiproxy/mtp/CaseManagement/` | Portal-internal unified investigation task/case management service. No public Microsoft API equivalent. |
| `^/apiproxy/mtp/GAIAMedeinaApi/` | Internal Microsoft Security Copilot (Medeina/GAIA) guided-response service. Provides AI-generated similar-incident recommendations. No public API equivalent. |
| `^/apiproxy/mtp/huntingService/alerts/([^/]+)/queryResults$` | Portal-internal: retrieves the Advanced Hunting KQL query results row that triggered this alert. No direct public API equivalent. To reproduce, fetch the detection rule at `https://api.security.microsoft.com/api/customdetections/{ruleId}` and re-run its query via `POST https://api.security.microsoft.com/api/advancedqueries/run`. |
| `^/apiproxy/mtp/huntingService/alerts/([^/]+)/timeline$` | Portal-internal MITRE ATT&CK timeline view for an alert (device/process events around the alert trigger time). No public API equivalent. |
| `^/apiproxy/mtp/huntingService/communityQueries$` | Portal-internal community query library loader. The underlying queries are publicly available at https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries but there is no API endpoint to retrieve them programmatically. |
| `^/apiproxy/mtp/huntingService/documentation/` | Portal-internal documentation endpoint that populates the Advanced Hunting help pane. Docs are publicly available at https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview but there is no structured API to retrieve them. |
| `^/apiproxy/mtp/huntingService/favorites` | Portal-internal user-specific favorite query store for the Advanced Hunting UI. No public Microsoft API equivalent. |
| `^/apiproxy/mtp/huntingService/guidedQueries/filterSchema$` | Portal-internal Guided Hunting UI filter schema definition (drives the visual query builder dropdowns). No public API equivalent. |
| `^/apiproxy/mtp/huntingService/queries` | Portal-internal saved/shared/scheduled query store. Scheduled queries published as custom detection rules can be retrieved via `GET https://api.security.microsoft.com/api/customdetections`. Shared and user-private saved queries have no public API equivalent. |
| `^/apiproxy/mtp/huntingService/reports/userHistory$` | Portal-internal Advanced Hunting usage telemetry (recently run queries). No public Microsoft API equivalent. |
| `^/apiproxy/mtp/huntingService/schema/functions$` | Portal-internal Advanced Hunting schema KQL built-in functions list. No public API equivalent; KQL function reference is at https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/functions. |
| `^/apiproxy/mtp/incidentQueue/incidents/count$` | Portal-internal incident count aggregation. No public API equivalent. As a workaround, use `GET https://api.security.microsoft.com/api/incidents` and count the response, or apply the same OData filters. |
| `^/apiproxy/mtp/incidents/([^/]+)/outbreaks$` | Portal-internal: associates an incident with Threat Analytics outbreak/campaign intelligence entries. No public Microsoft API equivalent. |
| `^/apiproxy/mtp/incidents/([^/]+)/riskfactors$` | Portal-internal ML-based risk factor scoring for an incident (used to populate attack complexity and scope indicators). No public Microsoft API equivalent. |
| `^/apiproxy/mtp/incidents/dsiMessageBarIndicators$` | Portal-internal Dynamic Security Intelligence (DSI) message bar banner data (used to display advisory banners on the incidents page). No public Microsoft API equivalent. |
| `^/apiproxy/mtp/phoenixValueReflectionApi/` | Portal-internal XDR value/ROI metrics service ("Phoenix"). Returns disruption statistics and summary totals shown on the Defender XDR overview page. No public Microsoft API equivalent. |
| `^/apiproxy/mtp/suppressionRulesService/RulesCount$` | Portal-internal suppression rule count aggregation. No public REST endpoint to retrieve a count of alert suppression rules. |
| `^/apiproxy/mtp/threatAnalytics/outbreaks/changeCount$` | Portal-internal Threat Analytics outbreak change counter (new outbreaks since the analyst's last visit). No public Microsoft API equivalent for this aggregated metric. |
| `^/apiproxy/mtp/unifiedActions/unifiedactions/Activities/([^/]+)$` | Portal-internal unified action/activity history for an incident. Returned HTTP 403 Forbidden even under the same auth context as other calls, suggesting it requires an additional role or is restricted to internal tenants. No public Microsoft API equivalent. |
| `^/apiproxy/mtp/userExposedRbacGroups/UserExposedRbacGroups$` | Portal-internal RBAC device group visibility metadata for the authenticated user. No public Microsoft API equivalent. |
| `^/apiproxy/mtp/userPreferences/api/mgmt/userpreferencesservice/userPreference/advanced_hunting$` | Portal-internal per-feature user preference store for Advanced Hunting UI settings (column layout, time range, etc.). No public Microsoft API equivalent. |
| `^/apiproxy/mtp/userPreferences/api/mgmt/userpreferencesservice/userPreference$` | Portal-internal global user preference store (portal-wide UI settings). No public Microsoft API equivalent. |
| `^/apiproxy/mtp/useServiceBaseUrl/ine/evidenceapiservice/evidence/alert/([^/]+)$` | Portal-internal Incident Navigator Engine (INE) — evidence entities linked to an alert (files, processes, IPs, etc.). No public Microsoft API equivalent. |
| `^/apiproxy/mtp/useServiceBaseUrl/ine/evidenceapiservice/evidence/incident/([^/]+)/count$` | Portal-internal INE — count of evidence entities associated with an incident. No public Microsoft API equivalent. |
| `^/apiproxy/mtp/useServiceBaseUrl/ine/evidenceapiservice/evidence/incident/([^/]+)$` | Portal-internal INE — evidence entities associated with an incident (attack story/evidence tab). No public Microsoft API equivalent. |
| `^/apiproxy/mtp/useServiceBaseUrl/ine/incidentgraphservice/incidentGraph/([^/]+)$` | Portal-internal INE — incident entity relationship graph used to render the Defender XDR attack story graph visualization. No public Microsoft API equivalent. |

## Mapped proxy calls

The 16 proxy paths that **are** captured and translated to their public API
equivalents are documented in [`research/api-mapping.json`](../research/api-mapping.json)
(entries where `graphApiUrl` is non-null).
