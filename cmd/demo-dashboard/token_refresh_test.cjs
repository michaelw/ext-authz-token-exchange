const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function dashboard() {
  const element = { addEventListener() {}, classList: { add() {}, remove() {} } };
  const context = vm.createContext({
    document: {
      addEventListener() {}, querySelectorAll: () => [], getElementById: () => element,
      documentElement: { removeAttribute() {}, setAttribute() {} },
    },
    window: { addEventListener() {} },
    localStorage: { getItem: () => "system", setItem() {} },
    fetch: () => new Promise(() => {}),
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "static/app.js"), "utf8"), context);
  let requests = 0;
  context.fetch = async () => ({ ok: true, json: async () => ({ bearer: `generated-${++requests}` }) });
  const evaluate = (code) => vm.runInContext(code, context);
  return { evaluate, requests: () => requests };
}

test("each generated-token run replaces cached tokens, including expired test tokens", async () => {
  for (const prefill of ["keycloak-subject", "keycloak-expired-subject", "keycloak-truncated-signature"]) {
    const app = dashboard();
    app.evaluate(`state.tokenValues.set("example", "expired-cached-token");
      globalThis.scenario = { name: "example", request: { token: { prefill: ${JSON.stringify(prefill)} } } };`);
    await app.evaluate("ensureScenarioToken(scenario)");
    assert.equal(app.evaluate('state.tokenValues.get("example")'), "generated-1");
    await app.evaluate("ensureScenarioToken(scenario)");
    assert.equal(app.evaluate('state.tokenValues.get("example")'), "generated-2");
    assert.equal(app.requests(), 2);
  }
});

test("manually supplied and cleared tokens remain unchanged", async () => {
  for (const value of ["manual-token", ""]) {
    const app = dashboard();
    app.evaluate(`state.tokenValues.set("example", ${JSON.stringify(value)});
      state.tokenOverrides.add("example");
      globalThis.scenario = { name: "example", request: { token: { prefill: "keycloak-subject" } } };`);
    await app.evaluate("ensureScenarioToken(scenario)");
    assert.equal(app.evaluate('state.tokenValues.get("example")'), value);
    assert.equal(app.requests(), 0);
  }
});

test("literal and unavailable scenarios do not request generated tokens", async () => {
  const app = dashboard();
  await app.evaluate('ensureScenarioToken({ name: "literal", request: { token: { prefill: "literal" } } })');
  await app.evaluate('ensureScenarioToken({ name: "unavailable", available: false, request: { token: { prefill: "keycloak-subject" } } })');
  assert.equal(app.requests(), 0);
});
