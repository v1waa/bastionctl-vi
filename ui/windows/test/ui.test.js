import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { shellMarkup, terminalOptions, managementTabs } from "../src/presentation.js";
import { ConsoleSession } from "../src/console-session.js";

const source = readFileSync(new URL("../src/main.js", import.meta.url), "utf8");
const css = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");

test("main window has two panes and a permanent terminal outside management", () => {
  assert.equal((shellMarkup.match(/<aside\b/g) || []).length, 1);
  assert.equal((shellMarkup.match(/<main\b/g) || []).length, 1);
  assert.match(shellMarkup, /id="add-server">Добавить<\/button>/);
  assert.equal((shellMarkup.match(/id="terminal-host"/g) || []).length, 1);
  assert.ok(shellMarkup.indexOf('id="terminal-host"') < shellMarkup.indexOf("</main>"));
  assert.ok(shellMarkup.indexOf('id="management-dialog"') > shellMarkup.indexOf("</main>"));
  assert.doesNotMatch(shellMarkup + source, /<svg\b|<img\b|brand-mark|\bicon\(|[✓×]/u);
});

test("console background is 15% transparent without fading its text", () => {
  assert.equal(terminalOptions.allowTransparency, true);
  assert.equal(terminalOptions.theme.background, "#00000000");
  assert.equal(terminalOptions.theme.foreground, "#eeeeee");
  assert.match(css, /\.terminal-surface\s*\{[^}]*background:\s*rgb\(18 18 18 \/ 85%\)/);
  for (const block of css.matchAll(/[^{}]*\b(?:terminal|xterm)[^{}]*\{([^}]*)\}/g)) {
    assert.doesNotMatch(block[1], /\bopacity\s*:/);
  }
});

test("all management sections remain reachable without a terminal tab", () => {
  assert.deepEqual(managementTabs.map(([id]) => id), ["overview", "security", "users", "services", "history", "settings"]);
  assert.equal((source.match(/\.open\(host\)/g) || []).length, 1);
  assert.match(source, /new ResizeObserver\(fitTerminal\)/);
  assert.doesNotMatch(source, /host\.innerHTML\s*=/);
  for (const method of ["TrustHostKey", "InstallPreview", "StartInstall", "RunSecurityAction", "CreateUser", "ConfigureXHTTP"]) {
    assert.ok(source.includes(`"${method}"`), method);
  }
  assert.match(source, /INSTALL \$\{server\.id\}/);
});

test("late SSH events cannot attach to an idle or different session", () => {
  const session = new ConsoleSession();
  assert.equal(session.accept({ kind: "connected", session_id: "old", server_id: "server-a" }), false);
  const generation = session.begin("server-a");
  assert.throws(() => session.begin("server-b"), /отключите/);
  assert.equal(session.accept({ kind: "connected", session_id: "wrong", server_id: "server-b" }), false);
  assert.equal(session.accept({ kind: "connected", session_id: "live", server_id: "server-a" }), true);
  assert.equal(session.accept({ kind: "data", session_id: "other", server_id: "server-a" }), false);
  session.started("live", generation);
  assert.equal(session.accept({ kind: "data", session_id: "live", server_id: "server-a" }), true);
  session.end("live");
  assert.equal(session.busy, false);
  assert.equal(session.accept({ kind: "data", session_id: "live", server_id: "server-a" }), false);
});

test("a close event before the start response does not resurrect a session", () => {
  const session = new ConsoleSession();
  const generation = session.begin("server-a");
  session.accept({ kind: "connected", session_id: "short", server_id: "server-a" });
  session.end("short");
  session.started("short", generation);
  assert.equal(session.id, "");
  assert.equal(session.busy, false);
});

test("late start responses cannot change a newer connection", () => {
  const session = new ConsoleSession();
  const old = session.begin("server-a");
  session.accept({ kind: "connected", session_id: "old", server_id: "server-a" });
  session.end("old");
  const next = session.begin("server-b");
  session.started("old", old);
  session.failed(old);
  assert.equal(session.starting, true);
  assert.equal(session.serverId, "server-b");
  session.started("new", next);
  assert.equal(session.id, "new");
});

test("release and frontend versions agree", () => {
  const version = readFileSync(new URL("../../../VERSION", import.meta.url), "utf8").trim();
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
  assert.equal(pkg.version, version);
  assert.equal(lock.version, version);
  assert.equal(lock.packages[""].version, version);
});
