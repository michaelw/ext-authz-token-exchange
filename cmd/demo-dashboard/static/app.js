const state = {
  scenarios: [],
  selected: null,
  results: new Map(),
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
  $("gateway-chip").textContent = `Gateway: ${data.baseURL}`;
  renderScenarioList();
  selectScenario(state.scenarios[0]?.name);
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

function renderSelected() {
  const scenario = state.selected;
  if (!scenario) {
    return;
  }
  const result = state.results.get(scenario.name);
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
  $("request-token").textContent = scenario.request.bearer ? `Bearer ${scenario.request.bearer}` : "<none>";
  $("tab-curl").textContent = result?.curl || buildCurlPreview(scenario);
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
  $("observed-auth").textContent = observed.upstreamAuthorization || "-";
  $("observed-error").textContent = observed.error || "-";
  $("observed-www").textContent = observed.wwwAuthenticate || "-";
  $("observed-cors").textContent = observed.corsOrigin || "-";
  $("observed-content-type").textContent = observed.contentType || "-";
  $("observed-elapsed").textContent = observed.elapsed || "-";
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
    "response-raw",
  ]) {
    $(id).textContent = "-";
  }
  $("response-preview").textContent = "Run a scenario to render the response.";
  $("response-format-toggle").hidden = true;
}

async function runScenario(name) {
  const scenario = state.scenarios.find((item) => item.name === name);
  if (!scenario) {
    return;
  }
  selectScenario(name);
  setPill("Running", "running");
  renderFlow(scenario, { running: true });
  try {
    const result = await api(`/api/scenarios/${encodeURIComponent(name)}/run`, { method: "POST" });
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
    renderStructuredPreview("json", observed);
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
  if (event.key === "Enter" && state.selected) {
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
$("theme-select").addEventListener("change", (event) => applyTheme(event.target.value));
for (const button of document.querySelectorAll(".format-button")) {
  button.addEventListener("click", () => renderStructuredPreview(button.dataset.format));
}

applyTheme(localStorage.getItem(themeStorageKey) || "system");
load().catch((error) => {
  $("scenario-list").textContent = error.message;
});
