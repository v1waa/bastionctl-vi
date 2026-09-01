import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

if (!process.env.PLAYWRIGHT_MODULE) throw new Error("PLAYWRIGHT_MODULE must name the CI-only Playwright installation");
const { chromium } = await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE).href);
const server = spawn(process.execPath, [resolve("ui/windows/node_modules/vite/bin/vite.js"), "--host", "127.0.0.1", "--port", "4173", "--strictPort"], {
  cwd: resolve("ui/windows"), stdio: ["ignore", "pipe", "pipe"]
});
let output = "";
server.stdout.on("data", (chunk) => { output += chunk; });
server.stderr.on("data", (chunk) => { output += chunk; });
let browser;
try {
  let ready = false;
  for (let attempt = 0; attempt < 50; attempt++) {
    if (server.exitCode !== null) throw new Error(output);
    try { ready = (await fetch("http://127.0.0.1:4173")).ok; } catch {}
    if (ready) break;
    await delay(200);
  }
  if (!ready) throw new Error(`Preview did not start: ${output}`);
  // GitHub's Ubuntu image supplies Chrome. No real SSH endpoint is contacted.
  browser = await chromium.launch({ channel: "chrome", headless: true, args: ["--no-sandbox"] });
  const page = await browser.newPage({ viewport: { width: 1280, height: 820 } });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.addInitScript(() => {
    const servers = [
      { id: "a", name: "Ubuntu A", target: "admin@192.0.2.1", port: 22, profile: "minimal", host_key_trusted: true },
      { id: "b", name: "Ubuntu B", target: "admin@192.0.2.2", port: 22, profile: "minimal", host_key_trusted: true }
    ];
    const events = {};
    window.smoke = { calls: [], events };
    window.runtime = { EventsOn: (name, callback) => { events[name] = callback; } };
    const emit = (kind, extra = {}) => events["terminal:event"]({ kind, session_id: "test-session", server_id: "a", ...extra });
    window.go = { desktop: { App: {
      InitialState: async () => ({ version: "2.2.0-test", platform: "windows/amd64", profiles: ["minimal", "web"], servers }),
      SecuritySettings: async () => ({ profile: "minimal", ssh_allowed_cidrs: "", allowed_tcp_ports: "", allowed_udp_ports: "", automatic_reboot_time: "03:30", backup_markers: "", backup_max_age_hours: 26 }),
      StartTerminal: async () => { window.smoke.calls.push("start"); emit("connected"); emit("data", { data: "Ubuntu test console\r\nadmin@ubuntu:~$ " }); return "test-session"; },
      TerminalInput: async (id, data) => { window.smoke.calls.push({ input: data, id }); },
      TerminalResize: async (id, cols, rows) => { window.smoke.calls.push({ resize: [cols, rows], id }); },
      StopTerminal: async () => { emit("closed"); },
      RunSecurityAction: async () => { window.smoke.calls.push("security-action"); throw new Error("Unexpected remote mutation"); }
    } } };
  });
  await page.goto("http://127.0.0.1:4173");
  await page.locator(".xterm").waitFor();
  assert.equal(await page.locator("svg, img, .brand, .icon").count(), 0);
  for (const [width, height] of [[1280, 820], [880, 560]]) {
    await page.setViewportSize({ width, height });
    const layout = await page.evaluate(() => {
      const left = document.querySelector(".sidebar").getBoundingClientRect();
      const right = document.querySelector(".workspace").getBoundingClientRect();
      const surface = document.querySelector(".terminal-surface");
      const host = document.querySelector("#terminal-host");
      return {
        separated: left.right <= right.left + 1, consoleWidth: host.clientWidth, consoleHeight: host.clientHeight,
        background: getComputedStyle(surface).backgroundColor, opacity: getComputedStyle(host).opacity,
        overflow: document.documentElement.scrollWidth > innerWidth
      };
    });
    assert.equal(layout.separated, true);
    assert.equal(layout.overflow, false);
    assert.ok(layout.consoleWidth > 550 && layout.consoleHeight > 400);
    assert.equal(layout.background, "rgba(18, 18, 18, 0.85)");
    assert.equal(layout.opacity, "1");
  }
  await page.setViewportSize({ width: 1280, height: 820 });
  await page.evaluate(() => { window.smoke.terminalElement = document.querySelector(".xterm"); });
  await page.locator("#terminal-toggle").click();
  await page.locator(".modal-submit").click();
  await page.waitForFunction(() => document.querySelector("#terminal-toggle")?.textContent === "Отключить");
  await page.locator('[data-id="b"]').click();
  assert.equal(await page.locator(".server-item.selected").getAttribute("data-id"), "a");
  await page.locator("#manage-server").click();
  await page.locator('[data-tab="settings"]').click();
  await page.locator("#s-profile").waitFor();
  await page.locator('[data-tab="security"]').click();
  await page.locator('[data-action="apply"]').click();
  await page.locator("#exact-confirm").fill("wrong");
  await page.locator(".modal-submit").click();
  await page.locator(".modal-body .toast.error").waitFor();
  assert.equal(await page.evaluate(() => window.smoke.calls.includes("security-action")), false);
  await page.locator(".modal-cancel").click();
  await page.locator("#management-close").click();
  assert.equal(await page.evaluate(() => window.smoke.terminalElement === document.querySelector(".xterm")), true);
  await page.locator("#terminal-host").click();
  await page.keyboard.type("echo test");
  await page.waitForFunction(() => window.smoke.calls.some((call) => call.input));
  await page.setViewportSize({ width: 1000, height: 700 });
  await page.waitForFunction(() => window.smoke.calls.some((call) => call.resize));
  await page.locator("#terminal-toggle").click();
  await page.locator('[data-id="b"]').click();
  assert.equal(await page.locator(".server-item.selected").getAttribute("data-id"), "b");
  await page.locator("#add-server").click();
  await page.locator("#add-id").waitFor();
  await page.keyboard.press("Escape");
  assert.equal(await page.locator("#modal-layer dialog").count(), 0);
  assert.deepEqual(errors, []);
  console.log("Browser smoke passed: two panes, gray theme, 15% transparency, persistent console, input/resize, confirmation and Escape.");
} finally {
  await browser?.close();
  server.kill("SIGTERM");
}
