const state = {
  scenarios: [],
  issuer: { label: "Issuer" },
  selected: null,
  results: new Map(),
  tokenValues: new Map(),
  tokenOverrides: new Set(),
  diagramRenderID: 0,
  mermaidInitialized: false,
  statusRefreshTimer: null,
  statusRefreshing: false,
  tokenTimeRefreshTimer: null,
  tokenVerifyTimer: null,
  tokenVerifyRequestID: 0,
  tokenVerification: { token: "", pending: false, response: null },
};

const $ = (id) => document.getElementById(id);
const themeStorageKey = "token-exchange-demo-theme";

function applyTheme(theme) {
  const selected = ["light", "dark", "system"].includes(theme) ? theme : "system";
  if (selected === "system") {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.setAttribute("data-theme", selected);
  }
  state.mermaidInitialized = false;
  renderDiagram();
  const picker = $("theme-select");
  if (picker) {
    picker.value = selected;
  }
  localStorage.setItem(themeStorageKey, selected);
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const body = await response.json();
  if (!response.ok && !body.scenario) {
    throw new Error(body.error || response.statusText);
  }
  return body;
}

async function load() {
  const data = await api("/api/scenarios");
  state.scenarios = data.scenarios;
  state.issuer = data.issuer || { label: "Issuer" };
  for (const scenario of state.scenarios) {
    if (!state.tokenValues.has(scenario.name)) {
      state.tokenValues.set(scenario.name, scenario.request?.bearer || "");
    }
  }
  await prefillScenarioTokens();
  $("gateway-chip").textContent = `Gateway: ${data.baseURL}`;
  $("scenario-config-chip").textContent = `Scenarios: ${state.issuer.name || "unknown"}`;
  $("scenario-config-chip").title = data.issuer?.scenarioConfig || "";
  $("issuer-node-label").textContent = state.issuer.label || "Issuer";
  $("issuer-logs-title").textContent = state.issuer.label || "Issuer";
  await refreshStatus({ showChecking: true });
  startStatusRefresh();
  startTokenTimeRefresh();
  renderScenarioList();
  selectScenario(state.scenarios[0]?.name);
}

function startStatusRefresh() {
  if (state.statusRefreshTimer) {
    return;
  }
  state.statusRefreshTimer = window.setInterval(() => {
    if (document.hidden) {
      return;
    }
    refreshStatus();
  }, 5000);
}

function startTokenTimeRefresh() {
  if (state.tokenTimeRefreshTimer) {
    return;
  }
  state.tokenTimeRefreshTimer = window.setInterval(() => {
    if (!document.hidden && state.selected) {
      renderInputTokenTimes();
      refreshTokenVerificationAtTimeBoundary();
    }
  }, 1000);
}

async function refreshStatus({ showChecking = false } = {}) {
  if (state.statusRefreshing) {
    return;
  }
  state.statusRefreshing = true;
  if (showChecking) {
    setStatusChip("plugin-status", "Plugin", { checking: true });
    setStatusChip("issuer-status", state.issuer.label || "Issuer", { checking: true });
  }
  try {
    const status = await api("/api/status");
    state.issuer.label = status.issuerLabel || state.issuer.label || "Issuer";
    setStatusChip("plugin-status", "Plugin", status.plugin);
    setStatusChip("issuer-status", state.issuer.label, status.issuer);
  } catch (error) {
    setStatusChip("plugin-status", "Plugin", { warning: error.message });
    setStatusChip("issuer-status", state.issuer.label || "Issuer", { warning: error.message });
  } finally {
    state.statusRefreshing = false;
  }
}

function setStatusChip(id, label, status = {}) {
  const chip = $(id);
  chip.classList.remove("good", "fail", "running");
  if (status.checking) {
    chip.classList.add("running");
    chip.textContent = `${label}: checking`;
    chip.title = "";
    return;
  }
  if (status.ready) {
    chip.classList.add("good");
    chip.textContent = `${label}: ready`;
  } else {
    chip.classList.add("fail");
    chip.textContent = `${label}: down`;
  }
  chip.title = status.warning || `${status.namespace || ""}/${status.deployment || ""} ${status.available || ""}`.trim();
}

function renderScenarioList() {
  const list = $("scenario-list");
  list.innerHTML = "";
  for (const scenario of state.scenarios) {
    const result = state.results.get(scenario.name);
    const button = document.createElement("button");
    button.className = [
      "scenario",
      scenario.name === state.selected?.name ? "active" : "",
      result?.passed === true ? "pass" : "",
      result?.passed === false ? "fail" : "",
    ].filter(Boolean).join(" ");
    button.type = "button";
    button.addEventListener("click", () => selectScenario(scenario.name));
    button.innerHTML = `
      <span class="stripe ${scenarioColor(scenario)}"></span>
      <span>
        <span class="scenario-name">${escapeHTML(scenario.name)}</span>
        <span class="scenario-summary">${escapeHTML(scenario.summary || "")}</span>
      </span>
    `;
    list.appendChild(button);
  }
}

function selectScenario(name) {
  state.selected = state.scenarios.find((scenario) => scenario.name === name) || null;
  renderScenarioList();
  renderSelected();
}

function tokenForScenario(scenario) {
  if (!scenario) {
    return "";
  }
  return state.tokenValues.has(scenario.name)
    ? state.tokenValues.get(scenario.name)
    : scenario.request?.bearer || "";
}

function effectiveScenario(scenario) {
  if (!scenario) {
    return null;
  }
  return {
    ...scenario,
    request: {
      ...(scenario.request || {}),
      bearer: normalizeBearerInput(tokenForScenario(scenario)),
    },
  };
}

function normalizeBearerInput(value) {
  value = String(value || "").trim();
  return value.toLowerCase().startsWith("bearer ")
    ? value.slice("bearer ".length).trim()
    : value;
}

async function prefillScenarioTokens() {
  for (const scenario of state.scenarios) {
    if (!shouldPrefillScenarioToken(scenario)) {
      continue;
    }
    try {
      const response = await api(`/api/scenarios/${encodeURIComponent(scenario.name)}/token`, { method: "POST" });
      if (!state.tokenOverrides.has(scenario.name)) {
        state.tokenValues.set(scenario.name, response.bearer || "");
      }
    } catch (error) {
      console.warn(`prefill token for ${scenario.name}: ${error.message}`);
    }
  }
}

function shouldPrefillScenarioToken(scenario) {
  if (state.tokenOverrides.has(scenario.name) || normalizeBearerInput(tokenForScenario(scenario))) {
    return false;
  }
  if (state.issuer.name !== "keycloak") {
    return false;
  }
  if (!scenario.exchange || scenario.exchange === "-") {
    return false;
  }
  return (scenario.expect?.status || 200) < 400;
}

function renderSelected() {
  const selected = state.selected;
  if (!selected) {
    return;
  }
  const scenario = effectiveScenario(selected);
  const result = state.results.get(selected.name);
  $("scenario-title").textContent = scenario.name;
  $("scenario-summary").textContent = scenario.summary || "";
  $("client-detail").textContent = `${scenario.request.method} ${scenario.request.path}`;
  $("plugin-detail").textContent = scenario.expect?.status === 200 ? "allow or exchange" : "deny or map error";
  $("policy-detail").textContent = scenario.policy || "-";
  $("issuer-detail").textContent = scenario.exchange || "-";
  $("issuer-summary").textContent = scenario.behavior?.summary || "-";
  $("issuer-behavior-detail").textContent = scenario.behavior?.detail || "No issuer behavior metadata for this scenario.";
  $("httpbin-detail").textContent = scenario.expect?.upstreamAuthorization || "upstream";
  $("request-method").textContent = scenario.request.method;
  $("request-path").textContent = scenario.request.path;
  setTokenDisplay($("request-token"), scenario.request.bearer ? `Bearer ${scenario.request.bearer}` : "");
  $("tab-curl").textContent = result?.curl || buildCurlPreview(scenario);
  renderInputTokenPanel(selected);
  renderDiagram(scenario, result);
  loadPolicy(scenario);

  if (!result) {
    setPill("Idle", "");
    clearObserved();
    renderFlow(scenario, null);
    return;
  }

  const observed = result.observed || {};
  setPill(result.passed ? "PASS" : "FAIL", result.passed ? "pass" : "fail");
  $("observed-status").textContent = observed.status || "-";
  setTokenDisplay($("observed-auth"), observed.upstreamAuthorization);
  setHTTPBinDetail(observed.upstreamAuthorization || scenario.expect?.upstreamAuthorization);
  $("observed-error").textContent = observed.error || "-";
  $("observed-www").textContent = observed.wwwAuthenticate || "-";
  $("observed-cors").textContent = observed.corsOrigin || "-";
  $("observed-content-type").textContent = observed.contentType || "-";
  $("observed-elapsed").textContent = observed.elapsed || "-";
  renderDecodedToken(observed.upstreamAuthorization);
  renderResponse(result);
  renderFlow(scenario, result);
}

function clearObserved() {
  for (const id of [
    "observed-status",
    "observed-auth",
    "observed-error",
    "observed-www",
    "observed-cors",
    "observed-content-type",
    "observed-elapsed",
    "jwt-issuer",
    "jwt-scenario",
    "jwt-subject",
    "jwt-scope",
    "jwt-resource",
    "jwt-audience",
    "jwt-grant",
    "jwt-client",
    "response-raw",
  ]) {
    $(id).textContent = "-";
  }
  $("response-preview").textContent = "Run a scenario to render the response.";
  $("response-format-toggle").hidden = true;
}

async function runScenario(name) {
  await refreshStatus();
  const selected = state.scenarios.find((item) => item.name === name);
  if (!selected) {
    return;
  }
  selectScenario(name);
  const scenario = effectiveScenario(selected);
  setPill("Running", "running");
  renderFlow(scenario, { running: true });
  try {
    const result = await api(`/api/scenarios/${encodeURIComponent(name)}/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ bearer: tokenForScenario(selected) }),
    });
    state.results.set(name, result);
  } catch (error) {
    state.results.set(name, {
      scenario,
      passed: false,
      failures: [{ label: "request", want: "success", got: error.message }],
      observed: {},
    });
  }
  renderScenarioList();
  renderSelected();
}

async function runAll() {
  await refreshStatus();
  await prefillScenarioTokens();
  $("run-all").disabled = true;
  try {
    for (const scenario of state.scenarios) {
      await runScenario(scenario.name);
    }
  } finally {
    $("run-all").disabled = false;
  }
}

async function loadPolicy(scenario = state.selected) {
  const ref = parsePolicyRef(scenario?.policy);
  if (!ref) {
    $("policy-title").textContent = "Policy";
    $("policy-text").textContent = "No matched ConfigMap policy for this scenario.";
    return;
  }
  $("policy-title").textContent = `${ref.namespace}/${ref.name}`;
  $("policy-text").textContent = "Loading policy...";
  try {
    const policy = await api(`/api/policies/${encodeURIComponent(ref.namespace)}/${encodeURIComponent(ref.name)}`);
    const prefix = policy.warning ? `Warning: ${policy.warning}\n\n` : "";
    $("policy-text").textContent = prefix + (policy.text || "ConfigMap does not contain data.config.yaml.");
  } catch (error) {
    $("policy-text").textContent = `Failed to load policy: ${error.message}`;
  }
}

function parsePolicyRef(policy) {
  if (!policy || policy === "-") {
    return null;
  }
  const parts = policy.split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return null;
  }
  return { namespace: parts[0], name: parts[1] };
}

function renderFlow(scenario, result) {
  const steps = ["client", "gateway", "plugin", "policy", "issuer", "httpbin"];
  for (const step of steps) {
    const node = document.querySelector(`[data-step="${step}"]`);
    node.classList.remove("active", "stop", "skip");
  }

  const status = result?.observed?.status || scenario.expect?.status;
  const isCORS = scenario.request.method === "OPTIONS" &&
    scenario.request.headers?.Origin &&
    scenario.request.headers?.["Access-Control-Request-Method"];
  const unmatched = !scenario.policy || scenario.policy === "-";
  const exchange = scenario.exchange && scenario.exchange !== "-";

  for (const step of ["client", "gateway", "plugin"]) {
    document.querySelector(`[data-step="${step}"]`).classList.add("active");
  }
  if (!unmatched) {
    document.querySelector('[data-step="policy"]').classList.add("active");
  }
  if (exchange && !isCORS) {
    document.querySelector('[data-step="issuer"]').classList.add("active");
  } else {
    document.querySelector('[data-step="issuer"]').classList.add("skip");
  }
  if (status === 200 || unmatched || isCORS) {
    document.querySelector('[data-step="httpbin"]').classList.add("active");
  }
  if (status >= 400) {
    document.querySelector('[data-step="plugin"]').classList.add("stop");
  }
}

async function renderDiagram(scenario = state.selected, result = state.results.get(state.selected?.name)) {
  const diagram = $("mermaid-diagram");
  const source = $("mermaid-source");
  const error = $("mermaid-error");
  if (!diagram || !source || !error) {
    return;
  }
  if (!scenario) {
    diagram.textContent = "Select a scenario.";
    source.textContent = "";
    error.hidden = true;
    return;
  }

  const mermaidSource = buildMermaidDiagram(scenario, result);
  const renderID = ++state.diagramRenderID;
  source.textContent = mermaidSource;
  error.hidden = true;

  const mermaid = window.mermaid;
  if (!mermaid) {
    diagram.textContent = "Loading Mermaid renderer...";
    return;
  }
  if (!state.mermaidInitialized) {
    const styles = getComputedStyle(document.documentElement);
    const dark = isDarkTheme();
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      themeVariables: {
        darkMode: dark,
        background: "transparent",
        mainBkg: styles.getPropertyValue("--surface-2").trim(),
        primaryColor: dark ? "#dbe7ff" : "#eef4ff",
        primaryBorderColor: styles.getPropertyValue("--blue").trim(),
        primaryTextColor: dark ? "#0f141b" : styles.getPropertyValue("--text").trim(),
        lineColor: dark ? "#a9b8d0" : "#314052",
        textColor: styles.getPropertyValue("--text").trim(),
        actorBkg: dark ? "#dbe7ff" : "#eef4ff",
        actorBorder: styles.getPropertyValue("--blue").trim(),
        actorTextColor: dark ? "#0f141b" : styles.getPropertyValue("--text").trim(),
        signalColor: styles.getPropertyValue("--text").trim(),
        signalTextColor: styles.getPropertyValue("--text").trim(),
        labelBoxBkgColor: styles.getPropertyValue("--surface").trim(),
        labelTextColor: styles.getPropertyValue("--text").trim(),
        noteBkgColor: styles.getPropertyValue("--accent-soft").trim(),
        noteTextColor: styles.getPropertyValue("--text").trim(),
        activationBkgColor: styles.getPropertyValue("--accent-soft").trim(),
        activationBorderColor: styles.getPropertyValue("--accent-border").trim(),
      },
      sequence: {
        mirrorActors: false,
        useMaxWidth: true,
      },
    });
    state.mermaidInitialized = true;
  }

  try {
    const rendered = await mermaid.render(`scenario-diagram-${renderID}`, mermaidSource);
    if (renderID !== state.diagramRenderID) {
      return;
    }
    diagram.innerHTML = rendered.svg;
    if (rendered.bindFunctions) {
      rendered.bindFunctions(diagram);
    }
  } catch (renderError) {
    diagram.textContent = "Mermaid could not render this scenario.";
    error.textContent = renderError.message || String(renderError);
    error.hidden = false;
  }
}

function isDarkTheme() {
  const theme = document.documentElement.getAttribute("data-theme");
  return theme === "dark" ||
    (theme !== "light" && window.matchMedia?.("(prefers-color-scheme: dark)").matches);
}

function buildMermaidDiagram(scenario, result) {
  const request = scenario.request || {};
  const expect = scenario.expect || {};
  const observed = result?.observed || {};
  const status = observed.status || expect.status || 200;
  const hasCORSHeaders = request.method === "OPTIONS" &&
    request.headers?.Origin &&
    request.headers?.["Access-Control-Request-Method"];
  const unmatched = !scenario.policy || scenario.policy === "-";
  const exchange = scenario.exchange && scenario.exchange !== "-";
  const lines = [
    "sequenceDiagram",
    "    participant Client",
    "    participant Gateway as \"Gateway API pod\"",
    "    participant Plugin as \"ext-authz plugin\"",
  ];
  if (!unmatched) {
    lines.push("    participant Policy as \"ConfigMap policy\"");
  }
  if (exchange && !hasCORSHeaders) {
    lines.push(`    participant Issuer as ${JSON.stringify(state.issuer.label || "Issuer")}`);
  }
  if (status < 400 || unmatched || hasCORSHeaders) {
    lines.push("    participant Httpbin as \"go-httpbin\"");
  }
  lines.push("");
  lines.push(`    Client->>Gateway: ${diagramText(requestLine(request))}`);
  lines.push("    Gateway->>Plugin: Envoy ext_authz Check");

  if (unmatched) {
    lines.push("    Plugin-->>Gateway: OK, no matching policy");
    lines.push(`    Gateway->>Httpbin: ${diagramText(upstreamLine(request, observed, expect))}`);
    lines.push(`    Httpbin-->>Client: ${diagramText(responseLine(status, "JSON echoed headers"))}`);
    return lines.join("\n");
  }

  lines.push(`    Plugin->>Policy: ${diagramText(`Match ${scenario.policy}`)}`);

  if (hasCORSHeaders) {
    lines.push("    Plugin-->>Gateway: OK without token exchange");
    lines.push(`    Gateway->>Httpbin: ${diagramText(`${request.method} ${request.path}`)}`);
    lines.push(`    Httpbin-->>Client: ${diagramText(responseLine(status, "CORS response headers"))}`);
    return lines.join("\n");
  }

  if (exchange) {
    lines.push(`    Plugin->>Issuer: ${diagramText(tokenExchangeLine(scenario))}`);
    if (status >= 400) {
      lines.push(`    Issuer-->>Plugin: ${diagramText(issuerErrorLine(status, observed, expect))}`);
      lines.push(`    Plugin-->>Client: ${diagramText(responseLine(status, sanitizedError(observed, expect)))}`);
      return lines.join("\n");
    }
    lines.push(`    Issuer-->>Plugin: ${diagramText(issuerSuccessLine(scenario, observed, expect))}`);
    lines.push("    Plugin-->>Gateway: OK, replace Authorization");
    lines.push(`    Gateway->>Httpbin: ${diagramText(upstreamLine(request, observed, expect))}`);
    lines.push(`    Httpbin-->>Client: ${diagramText(responseLine(status, "JSON echoed headers"))}`);
    return lines.join("\n");
  }

  if (status >= 400) {
    lines.push(`    Plugin-->>Client: ${diagramText(responseLine(status, sanitizedError(observed, expect)))}`);
    return lines.join("\n");
  }

  lines.push("    Plugin-->>Gateway: OK without token exchange");
  lines.push(`    Gateway->>Httpbin: ${diagramText(upstreamLine(request, observed, expect))}`);
  lines.push(`    Httpbin-->>Client: ${diagramText(responseLine(status, "JSON echoed headers"))}`);
  return lines.join("\n");
}

function requestLine(request) {
  const parts = [`${request.method} ${request.path}`];
  if (request.bearer) {
    parts.push(displayAuthorization(`Bearer ${request.bearer}`));
  }
  const headers = Object.entries(request.headers || {});
  if (headers.length) {
    parts.push(headers.map(([key, value]) => `${key}: ${value}`).join(", "));
  }
  return parts.join("<br/>");
}

function tokenExchangeLine(scenario) {
  const request = scenario.request || {};
  const parts = [`POST ${scenario.exchange}`];
  if (request.bearer) {
    parts.push(`subject_token=${displayAuthorization(`Bearer ${request.bearer}`)}`);
  }
  return parts.join("<br/>");
}

function issuerSuccessLine(scenario, observed, expect) {
  const auth = observed.upstreamAuthorization || expect.upstreamAuthorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : "";
  if (token) {
    const decoded = decodeJWT(token);
    return decoded ? `200 access_token=${compactTokenSummary(decoded.payload)}` : `200 access_token=${token}`;
  }
  return "200 access_token";
}

function issuerErrorLine(status, observed, expect) {
  const code = sanitizedError(observed, expect);
  if (status === 401 && (observed.wwwAuthenticate || expect.wwwAuthenticateContains)) {
    return "401 WWW-Authenticate";
  }
  return `${status} OAuth error ${code}`;
}

function upstreamLine(request, observed, expect) {
  const parts = [`${request.method} ${request.path}`];
  const auth = observed.upstreamAuthorization || expect.upstreamAuthorization;
  if (auth) {
    parts.push(`Authorization: ${displayAuthorization(auth)}`);
  }
  return parts.join("<br/>");
}

function responseLine(status, detail) {
  return detail ? `${status} ${detail}` : String(status);
}

function sanitizedError(observed, expect) {
  return observed.error || expect.error || "sanitized OAuth error";
}

function diagramText(value) {
  return String(value || "-")
    .replaceAll("\n", " ");
}

function setPill(label, klass) {
  const pill = $("result-pill");
  pill.className = ["result-pill", klass].filter(Boolean).join(" ");
  pill.textContent = label;
}

function formatResponse(result) {
  const lines = [];
  lines.push(`Request URL: ${result.requestURL || "-"}`);
  lines.push(`Passed: ${result.passed ? "yes" : "no"}`);
  if (result.failures?.length) {
    lines.push("");
    lines.push("Failures:");
    for (const failure of result.failures) {
      lines.push(`- ${failure.label}: expected ${failure.want}, got ${failure.got}`);
    }
  }
  lines.push("");
  lines.push("Observed:");
  lines.push(JSON.stringify(rawObserved(result.observed || {}), null, 2));
  return lines.join("\n");
}

function rawObserved(observed) {
  const { bodyBase64, prettyJSON, prettyYAML, ...raw } = observed;
  if (bodyBase64 && !raw.body) {
    raw.bodyBase64 = bodyBase64;
  }
  return raw;
}

function renderResponse(result) {
  $("response-raw").textContent = formatResponse(result);
  const observed = result.observed || {};
  const preview = $("response-preview");
  const toggle = $("response-format-toggle");
  preview.className = "response-preview";
  preview.textContent = "";
  toggle.hidden = true;

  const contentType = (observed.contentType || "").toLowerCase();
  if (contentType.startsWith("image/") && observed.bodyBase64) {
    const img = document.createElement("img");
    img.alt = "Response image preview";
    img.src = `data:${observed.contentType};base64,${observed.bodyBase64}`;
    preview.appendChild(img);
    return;
  }

  if (contentType.includes("html") && observed.body) {
    const iframe = document.createElement("iframe");
    iframe.title = "HTML response preview";
    iframe.sandbox = "";
    iframe.srcdoc = observed.body;
    preview.appendChild(iframe);
    return;
  }

  if (observed.prettyJSON || observed.prettyYAML) {
    toggle.hidden = false;
    renderStructuredPreview("yaml", observed);
    return;
  }

  if (isReasonableText(contentType, observed.body)) {
    preview.textContent = observed.body || "-";
    return;
  }

  preview.textContent = observed.bodyBase64
    ? "Binary response is available in the raw payload but has no visual preview."
    : "No response body.";
}

function renderStructuredPreview(format, observed = state.results.get(state.selected?.name)?.observed || {}) {
  const nextFormat = format === "yaml" ? "yaml" : "json";
  for (const button of document.querySelectorAll(".format-button")) {
    button.classList.toggle("active", button.dataset.format === nextFormat);
  }
  $("response-preview").textContent = nextFormat === "yaml"
    ? observed.prettyYAML || observed.prettyJSON || "-"
    : observed.prettyJSON || observed.prettyYAML || "-";
}

function renderInputTokenPanel(scenario = state.selected) {
  if (!scenario) {
    return;
  }
  const input = $("input-token");
  const raw = tokenForScenario(scenario);
  if (document.activeElement !== input) {
    input.value = raw;
  }
  const token = normalizeBearerInput(raw);
  const decoded = decodeJWT(token);
  $("input-token-format").textContent = token ? decoded ? "JWT" : "opaque token" : "-";
  $("input-token-algorithm").textContent = decoded?.header?.alg || "-";
  $("input-token-issuer").textContent = decoded?.payload?.iss || "-";
  $("input-token-subject").textContent = decoded?.payload?.sub || "-";
  $("input-token-scope").textContent = decoded?.payload?.scope || "-";
  $("input-token-audience").textContent = claimList(decoded?.payload?.aud);
  $("input-token-client").textContent = decoded?.payload?.azp || decoded?.payload?.client_id || "-";
  $("input-token-header").textContent = decoded ? JSON.stringify(decoded.header, null, 2) : "-";
  $("input-token-payload").textContent = decoded ? JSON.stringify(decoded.payload, null, 2) : "-";
  renderInputTokenTimes(decoded?.payload);
  renderTokenVerification(token, decoded);
}

function renderInputTokenTimes(payload = decodedInputPayload()) {
  const claims = [
    ["exp", "input-token-exp", "expires"],
    ["iat", "input-token-iat", "issued"],
    ["nbf", "input-token-nbf", "valid"],
    ["auth_time", "input-token-auth-time", "auth"],
  ];
  for (const [claim, id, mode] of claims) {
    $(id).textContent = formatJWTTime(payload?.[claim], mode);
  }
}

function refreshTokenVerificationAtTimeBoundary() {
  const token = normalizeBearerInput(tokenForScenario(state.selected));
  const decoded = decodeJWT(token);
  const status = state.tokenVerification.response?.status;
  if (!token || !decoded || state.tokenVerification.token !== token) {
    return;
  }
  const now = Date.now() / 1000;
  if (status === "signature verified" && Number.isFinite(decoded.payload?.exp) && decoded.payload.exp <= now) {
    state.tokenVerification = { token: "", pending: false, response: null };
    renderTokenVerification(token, decoded);
  }
  if (status === "not yet valid" && Number.isFinite(decoded.payload?.nbf) && decoded.payload.nbf <= now) {
    state.tokenVerification = { token: "", pending: false, response: null };
    renderTokenVerification(token, decoded);
  }
}

function decodedInputPayload() {
  const token = normalizeBearerInput(tokenForScenario(state.selected));
  return decodeJWT(token)?.payload || null;
}

function setTokenStatus(text, klass, title = "") {
  const status = $("token-status");
  status.className = ["token-status", klass].filter(Boolean).join(" ");
  status.textContent = text;
  status.title = title || "";
}

function renderTokenVerification(token, decoded) {
  if (!token) {
    state.tokenVerification = { token: "", pending: false, response: null };
    window.clearTimeout(state.tokenVerifyTimer);
    setTokenStatus("-", "");
    return;
  }
  if (!decoded) {
    state.tokenVerification = {
      token,
      pending: false,
      response: { format: "opaque token", status: "opaque token", verified: false },
    };
    window.clearTimeout(state.tokenVerifyTimer);
    setTokenStatus("opaque token", "");
    return;
  }

  const current = state.tokenVerification;
  if (current.token === token && current.response) {
    applyTokenVerification(current.response);
    return;
  }
  if (current.token === token && current.pending) {
    setTokenStatus("verifying signature...", "");
    return;
  }

  const requestID = ++state.tokenVerifyRequestID;
  state.tokenVerification = { token, pending: true, response: null };
  setTokenStatus("verifying signature...", "");
  window.clearTimeout(state.tokenVerifyTimer);
  state.tokenVerifyTimer = window.setTimeout(() => verifyToken(token, requestID), 250);
}

function applyTokenVerification(response) {
  if (response.format) {
    $("input-token-format").textContent = response.format;
  }
  if (response.algorithm) {
    $("input-token-algorithm").textContent = response.algorithm;
  }
  setTokenStatus(response.status || "-", tokenStatusClass(response), response.detail || "");
}

async function verifyToken(token, requestID) {
  try {
    const response = await api("/api/token/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    if (!isCurrentTokenVerification(token, requestID)) {
      return;
    }
    state.tokenVerification = { token, pending: false, response };
    applyTokenVerification(response);
  } catch (error) {
    if (!isCurrentTokenVerification(token, requestID)) {
      return;
    }
    const response = {
      format: "JWT",
      verified: false,
      status: "verification unavailable",
      detail: error.message,
    };
    state.tokenVerification = { token, pending: false, response };
    applyTokenVerification(response);
  }
}

function isCurrentTokenVerification(token, requestID) {
  return requestID === state.tokenVerifyRequestID &&
    normalizeBearerInput(tokenForScenario(state.selected)) === token;
}

function tokenStatusClass(response = {}) {
  if (response.verified || response.status === "signature verified") {
    return "good";
  }
  if ([
    "expired",
    "not yet valid",
    "signature invalid",
    "unsupported algorithm",
  ].includes(response.status)) {
    return "fail";
  }
  return "";
}

function handleTokenInput(event) {
  if (!state.selected) {
    return;
  }
  state.tokenValues.set(state.selected.name, event.target.value);
  state.tokenOverrides.add(state.selected.name);
  state.results.delete(state.selected.name);
  renderSelected();
  renderScenarioList();
}

async function fetchScenarioToken() {
  if (!state.selected) {
    return;
  }
  const scenario = state.selected;
  const button = $("fetch-token");
  button.disabled = true;
  setTokenStatus("fetching...", "");
  try {
    const response = await api(`/api/scenarios/${encodeURIComponent(scenario.name)}/token`, { method: "POST" });
    state.tokenValues.set(scenario.name, response.bearer || "");
    state.tokenOverrides.add(scenario.name);
    state.results.delete(scenario.name);
    renderSelected();
    renderScenarioList();
    if (response.warning) {
      setTokenStatus(response.warning, "");
    }
  } catch (error) {
    setTokenStatus(error.message, "fail");
  } finally {
    button.disabled = false;
  }
}

function clearScenarioToken() {
  if (!state.selected) {
    return;
  }
  state.tokenValues.set(state.selected.name, "");
  state.tokenOverrides.add(state.selected.name);
  state.results.delete(state.selected.name);
  renderSelected();
  renderScenarioList();
}

function copyScenarioToken() {
  if (!state.selected) {
    return;
  }
  copyText(tokenForScenario(state.selected), $("copy-input-token"));
}

function renderDecodedToken(auth) {
  const decoded = decodeBearerAuthorization(auth);
  const payload = decoded?.payload || {};
  $("jwt-issuer").textContent = payload.iss || "-";
  $("jwt-scenario").textContent = payload.scenario || "-";
  $("jwt-subject").textContent = payload.sub || "-";
  $("jwt-scope").textContent = payload.scope || "-";
  $("jwt-resource").textContent = claimList(payload.resource);
  $("jwt-audience").textContent = claimList(payload.aud);
  $("jwt-grant").textContent = payload.grant_type || "-";
  $("jwt-client").textContent = payload.azp || payload.client_id || "-";
}

function setHTTPBinDetail(auth) {
  const detail = $("httpbin-detail");
  if (!auth) {
    detail.textContent = "upstream";
    detail.removeAttribute("title");
    detail.removeAttribute("tabindex");
    return;
  }
  const decoded = decodeBearerAuthorization(auth);
  if (!decoded) {
    detail.textContent = auth;
    detail.removeAttribute("title");
    detail.removeAttribute("tabindex");
    return;
  }
  detail.textContent = compactTokenSummary(decoded.payload);
  detail.title = tokenTooltip(decoded);
  detail.tabIndex = 0;
}

function setTokenDisplay(element, auth) {
  element.textContent = "";
  if (!auth) {
    element.textContent = "-";
    return;
  }
  const decoded = decodeBearerAuthorization(auth);
  if (!decoded) {
    element.textContent = truncateMiddle(auth, 96);
    if (auth.length > 96) {
      element.title = auth;
    } else {
      element.removeAttribute("title");
    }
    return;
  }
  const wrapper = document.createElement("span");
  wrapper.className = "token-field";
  const token = document.createElement("span");
  token.className = "token-value";
  token.tabIndex = 0;
  token.textContent = truncateMiddle(auth, 96);
  token.title = tokenTooltip(decoded);
  token.setAttribute("aria-label", tokenTooltip(decoded));
  const copy = document.createElement("button");
  copy.className = "copy-token";
  copy.type = "button";
  copy.textContent = "Copy";
  copy.setAttribute("aria-label", "Copy full Authorization header");
  copy.addEventListener("click", () => copyText(auth, copy));
  wrapper.append(token, copy);
  element.appendChild(wrapper);
}

function displayAuthorization(auth) {
  const decoded = decodeBearerAuthorization(auth);
  return decoded ? `Bearer ${compactTokenSummary(decoded.payload)}` : auth;
}

function decodeBearerAuthorization(auth) {
  if (!auth?.startsWith("Bearer ")) {
    return null;
  }
  return decodeJWT(auth.slice("Bearer ".length));
}

function decodeJWT(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) {
    return null;
  }
  try {
    const header = base64URLDecodeJSON(parts[0]);
    const payload = base64URLDecodeJSON(parts[1]);
    if (!header || !payload) {
      return null;
    }
    return {
      header,
      payload,
      signatureStatus: header.alg === "none" && parts[2] === "" ? "unsigned JWT" : "signature not verified",
    };
  } catch {
    return null;
  }
}

function base64URLDecodeJSON(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

function compactTokenSummary(payload = {}) {
  return [
    "JWT",
    payload.scenario ? `scenario=${payload.scenario}` : "",
    payload.sub ? `sub=${payload.sub}` : "",
    payload.azp ? `azp=${payload.azp}` : "",
    payload.aud ? `aud=${claimList(payload.aud)}` : "",
  ].filter(Boolean).join(" ");
}

function tokenTooltip(decoded) {
  const payload = decoded?.payload || {};
  return [
    `signature: ${decoded?.signatureStatus || "-"}`,
    `iss: ${payload.iss || "-"}`,
    `scenario: ${payload.scenario || "-"}`,
    `sub: ${payload.sub || "-"}`,
    `scope: ${payload.scope || "-"}`,
    `resource: ${claimList(payload.resource)}`,
    `aud: ${claimList(payload.aud)}`,
    `grant_type: ${payload.grant_type || "-"}`,
    `client: ${payload.azp || payload.client_id || "-"}`,
  ].join("\n");
}

function claimList(value) {
  if (Array.isArray(value)) {
    return value.length ? value.join(", ") : "-";
  }
  return value || "-";
}

function formatJWTTime(value, mode) {
  if (!Number.isFinite(value)) {
    return "-";
  }
  const date = new Date(value * 1000);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  const local = date.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  });
  const delta = date.getTime() - Date.now();
  return `${local} (${relativeTime(delta, mode)})`;
}

function relativeTime(deltaMs, mode) {
  const past = deltaMs < 0;
  const absSeconds = Math.floor(Math.abs(deltaMs) / 1000);
  const units = [
    ["year", 365 * 24 * 60 * 60],
    ["month", 30 * 24 * 60 * 60],
    ["day", 24 * 60 * 60],
    ["hour", 60 * 60],
    ["minute", 60],
    ["second", 1],
  ];
  const [unit, seconds] = units.find(([, size]) => absSeconds >= size) || units[units.length - 1];
  const amount = Math.max(1, Math.floor(absSeconds / seconds));
  const label = `${amount} ${unit}${amount === 1 ? "" : "s"}`;
  if (mode === "expires") {
    return past ? `expired ${label} ago` : `in ${label}`;
  }
  if (mode === "valid") {
    return past ? `${label} ago` : `in ${label}`;
  }
  return past ? `${label} ago` : `in ${label}`;
}

function truncateMiddle(value, maxLength) {
  value = String(value || "");
  if (value.length <= maxLength) {
    return value;
  }
  const keepStart = Math.ceil((maxLength - 1) * 0.65);
  const keepEnd = Math.floor((maxLength - 1) * 0.35);
  return `${value.slice(0, keepStart)}…${value.slice(value.length - keepEnd)}`;
}

async function copyText(value, button) {
  try {
    await navigator.clipboard.writeText(value);
    const original = button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => {
      button.textContent = original;
    }, 1200);
  } catch {
    button.textContent = "Copy failed";
  }
}

function isReasonableText(contentType, body) {
  if (!body || body.length > 256 * 1024) {
    return false;
  }
  return contentType.startsWith("text/") ||
    contentType.includes("xml") ||
    contentType.includes("yaml") ||
    contentType.includes("x-yaml");
}

function buildCurlPreview(scenario) {
  const parts = ["curl -sk", "-X", quote(scenario.request.method)];
  if (scenario.request.bearer) {
    parts.push("-H", quote(`Authorization: Bearer ${scenario.request.bearer}`));
  }
  for (const [key, value] of Object.entries(scenario.request.headers || {})) {
    parts.push("-H", quote(`${key}: ${value}`));
  }
  parts.push(quote(scenario.request.path));
  return parts.join(" ");
}

async function refreshLogs() {
  await refreshStatus();
  $("plugin-logs").textContent = "Loading...";
  $("issuer-logs").textContent = "Loading...";
  const [plugin, issuer] = await Promise.all([
    api("/api/logs/plugin").catch((error) => ({ logs: "", warning: error.message })),
    api("/api/logs/issuer").catch((error) => ({ logs: "", warning: error.message })),
  ]);
  $("plugin-logs").textContent = plugin.warning ? `${plugin.warning}\n${plugin.logs || ""}` : plugin.logs;
  $("issuer-logs").textContent = issuer.warning ? `${issuer.warning}\n${issuer.logs || ""}` : issuer.logs;
}

function scenarioColor(scenario) {
  const text = `${scenario.name} ${scenario.policy || ""}`;
  if (text.includes("yellow")) return "yellow";
  if (text.includes("red")) return "red";
  if (text.includes("blue")) return "blue";
  return "";
}

function quote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

document.addEventListener("click", (event) => {
  const scenarioButton = event.target.closest(".scenario");
  if (scenarioButton && event.detail === 2 && state.selected) {
    runScenario(state.selected.name);
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && state.selected && !event.target.closest("textarea, input, select, button")) {
    runScenario(state.selected.name);
  }
});

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    for (const item of document.querySelectorAll(".tab, .tab-panel")) {
      item.classList.remove("active");
    }
    tab.classList.add("active");
    $(`tab-${tab.dataset.tab}`).classList.add("active");
    if (tab.dataset.tab === "diagram") {
      renderDiagram();
    }
  });
}

$("run-all").addEventListener("click", runAll);
$("run-selected").addEventListener("click", () => {
  if (state.selected) {
    runScenario(state.selected.name);
  }
});
$("refresh-logs").addEventListener("click", refreshLogs);
$("refresh-policy").addEventListener("click", () => loadPolicy());
$("input-token").addEventListener("input", handleTokenInput);
$("fetch-token").addEventListener("click", fetchScenarioToken);
$("clear-token").addEventListener("click", clearScenarioToken);
$("copy-input-token").addEventListener("click", copyScenarioToken);
$("theme-select").addEventListener("change", (event) => applyTheme(event.target.value));
for (const button of document.querySelectorAll(".format-button")) {
  button.addEventListener("click", () => renderStructuredPreview(button.dataset.format));
}

window.addEventListener("mermaid-ready", () => renderDiagram());
applyTheme(localStorage.getItem(themeStorageKey) || "system");
load().catch((error) => {
  $("scenario-list").textContent = error.message;
});
