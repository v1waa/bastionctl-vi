import "@xterm/xterm/css/xterm.css";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "./styles.css";

const apiPath = "desktop";
const state = {
  meta: null,
  servers: [],
  selected: "",
  tab: "overview",
  terminal: null,
	terminalDecoder: new TextDecoder(),
  fit: null,
  session: "",
  operation: null,
  fingerprint: null,
  busy: false
};

const app = document.querySelector("#app");

const demoServer = {
  id: "prod-1", name: "Production", target: "bastion@203.0.113.10", port: 22,
  profile: "web", identity: "C:\\Users\\admin\\.config\\bastionctl\\servers\\prod-1\\id_ed25519",
  bootstrap_pending: false, host_key_trusted: true, last_action: "audit", last_status: "ok",
  last_seen_at: new Date().toISOString()
};

const demoBackend = {
  InitialState: async () => ({ version: "2.0.0-dev", platform: "windows/amd64", state_root: "C:\\Users\\admin\\AppData\\Roaming\\bastionctl", profiles: ["minimal", "web", "docker-host", "wireguard", "database"], servers: [demoServer] }),
  SecuritySettings: async () => ({ profile: "web", manage_ssh: true, manage_firewall: true, manage_fail2ban: true, manage_automatic_updates: true, manage_auditd: true, manage_apparmor: true, manage_time_sync: true, password_authentication: false, permit_root_login: false, ssh_allowed_cidrs: "198.51.100.24/32", allowed_tcp_ports: "80, 443", allowed_udp_ports: "", automatic_reboot: false, automatic_reboot_time: "03:30", backup_markers: "", backup_max_age_hours: 26, backup_required: false }),
  History: async () => [{ action: "audit", timestamp: new Date().toISOString(), has_failures: false, path: "history/prod-1/latest-audit.json" }],
	AuditAll: async () => [{ server: demoServer, operation: { report: { summary: { fail: 0 } } } }],
  RunSecurityAction: async (_request) => ({ server: demoServer, report: { action: _request.action, finished_at: new Date().toISOString(), summary: { pass: 9, fail: 0, warn: 1, changed: 0 }, results: [{ control: "ssh-policy", status: "pass", message: "SSH policy соответствует профилю" }, { control: "firewall", status: "warn", message: "Проверьте опубликованные Docker-порты" }], warnings: [] } }),
  ProbeHostKey: async () => ({ target: demoServer.target, address: "[203.0.113.10]:22", algorithm: "ssh-ed25519", fingerprint: "SHA256:DEMO-fingerprint-for-preview", trusted: true, changed: false }),
  SaveSecuritySettings: async () => {}, ApplyProfile: async () => {},
	UpdateServer: async () => demoServer, RemoveServer: async () => {},
  CaptureSnapshot: async () => ({ baseline_created: false, diff: { changes: [] } }),
	XHTTP: async () => ({ configured: false, config: {}, guide: [] }), ConfigureXHTTP: async () => ({}),
  TerminalInput: async () => {}, TerminalResize: async () => {}, StopTerminal: async () => {}
};

function backend() {
  const service = window.go?.[apiPath]?.App;
	if (!service && import.meta.env.DEV) return demoBackend;
  if (!service) throw new Error("Desktop backend ещё не готов");
  return service;
}

async function call(method, ...args) {
  const fn = backend()[method];
  if (typeof fn !== "function") throw new Error(`Метод ${method} недоступен`);
  return fn(...args);
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function selectedServer() {
  return state.servers.find((item) => item.id === state.selected) || null;
}

function statusText(server) {
  if (server.bootstrap_pending) return "Требуется первый вход";
  if (!server.host_key_trusted) return "Fingerprint не закреплён";
  if (server.last_status === "ok") return "Защищён";
  if (server.last_status === "fail") return "Есть проблемы";
  if (server.last_status === "drift") return "Обнаружены изменения";
  return "Не проверен";
}

function statusClass(server) {
  if (server.bootstrap_pending || !server.host_key_trusted) return "warning";
  if (server.last_status === "ok") return "ok";
  if (server.last_status === "fail") return "danger";
  return "neutral";
}

function icon(name) {
  const icons = {
    server: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><circle cx="7" cy="7" r="1"/><circle cx="7" cy="17" r="1"/></svg>',
    shield: '<svg viewBox="0 0 24 24"><path d="M12 3 4.5 6v5.4c0 4.5 3 8.3 7.5 9.6 4.5-1.3 7.5-5.1 7.5-9.6V6L12 3Z"/><path d="m9 12 2 2 4-4"/></svg>',
    terminal: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/></svg>',
    users: '<svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3"/><path d="M3.5 19c.5-4 2.3-6 5.5-6s5 2 5.5 6M16 5.5a3 3 0 0 1 0 5.8M17 13c2.2.6 3.3 2.5 3.5 5"/></svg>',
    history: '<svg viewBox="0 0 24 24"><path d="M4 12a8 8 0 1 0 2-5.3L4 9"/><path d="M4 4v5h5M12 7v5l3 2"/></svg>',
    settings: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19 13.5v-3l-2-.7-.5-1.2.9-1.9-2.1-2.1-1.9.9-1.2-.5-.7-2h-3l-.7 2-1.2.5-1.9-.9-2.1 2.1.9 1.9-.5 1.2-2 .7v3l2 .7.5 1.2-.9 1.9 2.1 2.1 1.9-.9 1.2.5.7 2h3l.7-2 1.2-.5 1.9.9 2.1-2.1-.9-1.9.5-1.2 2-.7Z"/></svg>',
    plus: '<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
    refresh: '<svg viewBox="0 0 24 24"><path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 8A7 7 0 0 1 18.5 7M17.9 16A7 7 0 0 1 5.5 17"/></svg>'
  };
  return `<span class="icon">${icons[name] || ""}</span>`;
}

function shell() {
  app.innerHTML = `
    <div class="shell">
      <aside class="sidebar">
        <div class="brand"><span class="brand-mark">B</span><div><strong>bastionctl</strong><small>Ubuntu control</small></div></div>
        <div class="sidebar-heading"><span>Серверы</span><button class="icon-button" id="refresh" title="Обновить">${icon("refresh")}</button></div>
        <div class="server-list" id="server-list"></div>
		<div class="sidebar-actions"><button class="add-server" id="add-server">${icon("plus")}Добавить сервер</button><button class="audit-all" id="audit-all">${icon("shield")}Аудит всех</button></div>
        <div class="sidebar-footer"><span class="pulse"></span><span id="version">desktop</span></div>
      </aside>
      <main class="workspace">
        <header class="topbar" id="topbar"></header>
        <nav class="tabs" id="tabs"></nav>
        <section class="content" id="content"></section>
      </main>
    </div>
    <div class="modal-layer" id="modal-layer"></div>
    <div class="toasts" id="toasts"></div>`;
  document.querySelector("#refresh").addEventListener("click", refresh);
  document.querySelector("#add-server").addEventListener("click", openAddServer);
	document.querySelector("#audit-all").addEventListener("click", auditAll);
}

function render() {
  renderServers();
  renderTopbar();
  renderTabs();
  renderContent();
}

function renderServers() {
  const list = document.querySelector("#server-list");
  if (!state.servers.length) {
    list.innerHTML = '<div class="empty-sidebar">Добавьте первый Ubuntu‑сервер</div>';
    return;
  }
  list.innerHTML = state.servers.map((server) => `
    <button class="server-item ${server.id === state.selected ? "selected" : ""}" data-id="${esc(server.id)}">
      <span class="server-icon">${icon("server")}</span>
      <span class="server-copy"><strong>${esc(server.name)}</strong><small>${esc(server.target)}:${server.port}</small></span>
      <span class="status-dot ${statusClass(server)}"></span>
    </button>`).join("");
  list.querySelectorAll(".server-item").forEach((button) => button.addEventListener("click", () => selectServer(button.dataset.id)));
}

function renderTopbar() {
  const bar = document.querySelector("#topbar");
  const server = selectedServer();
  if (!server) {
    bar.innerHTML = '<div><h1>Серверы</h1><p>Единое управление безопасностью Ubuntu</p></div>';
    return;
  }
  bar.innerHTML = `
    <div><h1>${esc(server.name)}</h1><p>${esc(server.target)} · SSH ${server.port} · ${esc(server.profile)}</p></div>
    <div class="server-state ${statusClass(server)}"><span class="status-dot ${statusClass(server)}"></span>${esc(statusText(server))}</div>`;
}

const tabs = [
  ["overview", "server", "Обзор"],
  ["security", "shield", "Защита"],
  ["terminal", "terminal", "Консоль"],
  ["users", "users", "Пользователи"],
	["services", "shield", "Сервисы"],
  ["history", "history", "История"],
  ["settings", "settings", "Настройки"]
];

function renderTabs() {
  const nav = document.querySelector("#tabs");
  if (!selectedServer()) {
    nav.innerHTML = "";
    return;
  }
  nav.innerHTML = tabs.map(([id, glyph, label]) => `<button class="tab ${state.tab === id ? "active" : ""}" data-tab="${id}">${icon(glyph)}${label}</button>`).join("");
  nav.querySelectorAll(".tab").forEach((button) => button.addEventListener("click", () => {
    state.tab = button.dataset.tab;
    renderTabs();
    renderContent();
  }));
}

function renderContent() {
  const content = document.querySelector("#content");
  const server = selectedServer();
  if (!server) {
    content.innerHTML = `<div class="welcome"><div class="welcome-icon">${icon("shield")}</div><h2>Начните с подключения сервера</h2><p>Понадобятся IP‑адрес, SSH‑пользователь и доступ к панели провайдера для сверки fingerprint.</p><button class="primary" id="welcome-add">Добавить Ubuntu‑сервер</button></div>`;
    document.querySelector("#welcome-add").addEventListener("click", openAddServer);
    return;
  }
  const views = { overview: overviewView, security: securityView, terminal: terminalView, users: usersView, services: servicesView, history: historyView, settings: settingsView };
  views[state.tab]?.(content, server);
}

function overviewView(content, server) {
  const lastSeen = server.last_seen_at && !server.last_seen_at.startsWith("0001-") ? new Date(server.last_seen_at).toLocaleString("ru-RU") : "ещё не подключался";
  content.innerHTML = `
    <div class="grid metrics">
      <article class="metric"><span>Состояние</span><strong>${esc(statusText(server))}</strong><small>Последнее действие: ${esc(server.last_action || "—")}</small></article>
      <article class="metric"><span>SSH‑доверие</span><strong>${server.host_key_trusted ? "Fingerprint закреплён" : "Требует проверки"}</strong><small>Отдельное хранилище для сервера</small></article>
      <article class="metric"><span>Последняя связь</span><strong>${esc(lastSeen)}</strong><small>${esc(server.target)}:${server.port}</small></article>
    </div>
    <div class="grid two">
      <article class="panel"><div class="panel-title"><div><h2>Быстрый старт</h2><p>Безопасная последовательность подключения</p></div></div><div class="steps">
        ${step(1, "Сверить SSH fingerprint", server.host_key_trusted, "fingerprint")}
        ${step(2, "Завершить вход по паролю", !server.bootstrap_pending, "bootstrap", !server.bootstrap_pending)}
        ${step(3, "Установить серверный компонент", server.last_action === "install" && server.last_status === "ok", "install")}
        ${step(4, "Выполнить аудит", server.last_action === "audit", "audit")}
      </div></article>
      <article class="panel"><div class="panel-title"><div><h2>Сервер</h2><p>Локальная запись администратора</p></div></div>
        <dl class="details"><div><dt>ID</dt><dd>${esc(server.id)}</dd></div><div><dt>Адрес</dt><dd>${esc(server.target)}:${server.port}</dd></div><div><dt>Профиль</dt><dd>${esc(server.profile)}</dd></div><div><dt>Ключ</dt><dd title="${esc(server.identity)}">${esc(server.identity || "SSH agent")}</dd></div></dl>
      </article>
    </div>`;
  content.querySelectorAll("[data-step]").forEach((button) => button.addEventListener("click", () => runStep(button.dataset.step, server)));
}

function step(number, label, done, action, disabled = false) {
  return `<button class="step ${done ? "done" : ""}" data-step="${action}" ${disabled ? "disabled" : ""}><span>${done ? "✓" : number}</span><strong>${label}</strong><small>${done ? "Готово" : "Открыть"}</small></button>`;
}

async function runStep(action, server) {
  if (action === "fingerprint") return hostKeyFlow(server);
  if (action === "bootstrap") return openConnect(server, true);
  if (action === "install") return installServer(server);
  if (action === "audit") {
    state.tab = "security";
    render();
    return runSecurity("audit");
  }
}

function securityView(content) {
  content.innerHTML = `
    <div class="section-head"><div><h2>Политика безопасности</h2><p>Сначала просмотрите план. Применение требует точного подтверждения.</p></div><div class="head-actions"><input id="security-passphrase" type="password" placeholder="Passphrase ключа, если нужен"><button class="secondary" id="refresh-settings">Настроить политику</button></div></div>
    <div class="action-grid">
      <button class="action-card" data-action="audit"><span>${icon("shield")}</span><strong>Аудит</strong><small>Только чтение, без изменений</small></button>
      <button class="action-card" data-action="plan"><span>${icon("history")}</span><strong>План</strong><small>Показать предстоящие изменения</small></button>
      <button class="action-card accent" data-action="apply"><span>${icon("refresh")}</span><strong>Применить</strong><small>Изменить только управляемую политику</small></button>
    </div>
    <article class="panel report-panel"><div class="panel-title"><div><h2>Результат</h2><p id="report-caption">Выберите действие</p></div></div><div id="report"><div class="empty-result">Отчёт появится здесь</div></div></article>
    <details class="danger-zone"><summary>Сброс управляемой политики</summary><p>Сохраняет пользователей, домашние каталоги, ключи и данные приложений. SSH‑доступ не удаляется, если это может заблокировать администратора.</p><div class="button-row"><button class="secondary" data-action="reset-plan">План сброса</button><button class="danger-button" data-action="reset">Выполнить сброс</button></div></details>`;
  content.querySelectorAll("[data-action]").forEach((button) => button.addEventListener("click", () => runSecurity(button.dataset.action)));
  document.querySelector("#refresh-settings").addEventListener("click", () => { state.tab = "settings"; render(); });
  if (state.operation) renderReport(state.operation);
}

async function runSecurity(action) {
  const server = selectedServer();
  if (!server) return;
  if (!server.host_key_trusted) return hostKeyFlow(server);
  let confirmation = "";
  if (action === "apply" || action === "reset") {
    const verb = action === "apply" ? "APPLY" : "RESET";
    confirmation = await confirmText({
      title: action === "apply" ? "Применить план" : "Сбросить политику",
      text: `Введите ${verb} ${server.id}. Текущая SSH‑сессия должна оставаться открытой, а rescue‑консоль — доступной.`,
      expected: `${verb} ${server.id}`,
      dangerous: action === "reset"
    });
    if (!confirmation) return;
  }
  setBusy(true, action === "audit" ? "Выполняется аудит…" : "Выполняется операция…");
  try {
	const passphrase = value("security-passphrase");
    state.operation = await call("RunSecurityAction", { server_id: server.id, action, confirmation, passphrase });
    await refresh(false);
    if (state.tab === "security") renderReport(state.operation);
    toast("Операция завершена", state.operation.report?.summary?.fail ? "warning" : "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(false);
  }
}

function renderReport(operation) {
  const target = document.querySelector("#report");
  if (!target || !operation?.report) return;
  const report = operation.report;
  const summary = report.summary || {};
  document.querySelector("#report-caption").textContent = `${report.action} · ${new Date(report.finished_at).toLocaleString("ru-RU")}`;
  target.innerHTML = `
    <div class="summary-row"><span class="ok">${summary.pass || 0} пройдено</span><span class="danger">${summary.fail || 0} ошибок</span><span class="warning">${summary.warn || 0} замечаний</span><span>${summary.changed || 0} изменений</span></div>
    <div class="results">${(report.results || []).map((item) => `<div class="result"><span class="result-status ${esc(item.status)}">${esc(item.status)}</span><div><strong>${esc(item.control)}</strong><p>${esc(item.message)}</p>${details(item.details)}</div></div>`).join("")}</div>
    ${(report.warnings || []).map((item) => `<div class="notice warning">${esc(item)}</div>`).join("")}`;
}

function details(values) {
  if (!values) return "";
  return `<dl class="result-details">${Object.entries(values).map(([key, value]) => `<div><dt>${esc(key)}</dt><dd>${esc(value)}</dd></div>`).join("")}</dl>`;
}

function terminalView(content, server) {
  content.innerHTML = `
    <div class="terminal-shell">
      <div class="terminal-toolbar"><div><span class="terminal-light ${state.session ? "connected" : ""}"></span><strong>${state.session ? "Подключено" : "Отключено"}</strong><small>${esc(server.target)}:${server.port}</small></div><div class="button-row"><button class="secondary" id="terminal-clear">Очистить</button><button class="${state.session ? "danger-button" : "primary"}" id="terminal-toggle">${state.session ? "Отключить" : server.bootstrap_pending ? "Первый вход" : "Подключить"}</button></div></div>
      <div id="terminal-host" class="terminal-host"></div>
      <div class="terminal-note">Команды выполняются напрямую на выбранном сервере. bastionctl не записывает ввод и вывод консоли.</div>
    </div>`;
  ensureTerminal();
  document.querySelector("#terminal-clear").addEventListener("click", () => state.terminal?.clear());
  document.querySelector("#terminal-toggle").addEventListener("click", async () => {
    if (state.session) {
      try { await call("StopTerminal", state.session); } catch (_) {}
      state.session = "";
      renderContent();
    } else {
      openConnect(server, server.bootstrap_pending);
    }
  });
}

function ensureTerminal() {
  const host = document.querySelector("#terminal-host");
  if (!host) return;
  if (!state.terminal) {
    state.terminal = new Terminal({
      cursorBlink: true,
      convertEol: false,
      fontFamily: '"Cascadia Mono", Consolas, monospace',
      fontSize: 14,
      lineHeight: 1.25,
      scrollback: 6000,
      theme: { background: "#0b0d10", foreground: "#d7dde5", cursor: "#7dd3fc", selectionBackground: "#21445a" }
    });
    state.fit = new FitAddon();
    state.terminal.loadAddon(state.fit);
    state.terminal.onData((data) => {
      if (state.session) call("TerminalInput", state.session, data).catch(showError);
    });
    state.terminal.onResize(({ cols, rows }) => {
      if (state.session) call("TerminalResize", state.session, cols, rows).catch(() => {});
    });
  }
  if (state.terminal.element?.parentElement !== host) {
    host.innerHTML = "";
    state.terminal.open(host);
  }
  requestAnimationFrame(() => state.fit.fit());
}

async function openConnect(server, bootstrap) {
  if (!server.host_key_trusted) {
    await hostKeyFlow(server);
    return;
  }
  const body = bootstrap ? `
    <div class="notice">Пароль используется только для этого SSH‑подключения и не сохраняется. Если вход выполняется от root, в консоли потребуется задать sudo‑пароль новому администратору.</div>
    ${field("Одноразовый SSH‑пароль", "connect-password", "password", "", true)}` : `
    ${field("Пароль ключа (если ключ зашифрован)", "connect-passphrase", "password")}
    ${field("SSH‑пароль (необязательно)", "connect-password", "password")}`;
  modal({
    title: bootstrap ? "Первый вход" : "Подключение к консоли",
    body,
    submit: bootstrap ? "Подключиться и установить ключ" : "Подключиться",
    onSubmit: async () => {
	  const password = document.querySelector("#connect-password")?.value || "";
	  const passphrase = document.querySelector("#connect-passphrase")?.value || "";
      closeModal();
      state.tab = "terminal";
      render();
      ensureTerminal();
      state.terminal.writeln(`\r\n\x1b[90mПодключение к ${bootstrap ? server.bootstrap_target : server.target}…\x1b[0m`);
      const size = { columns: state.terminal.cols || 100, rows: state.terminal.rows || 30 };
      try {
        state.session = bootstrap
          ? await call("StartBootstrap", { server_id: server.id, password, ...size })
          : await call("StartTerminal", { server_id: server.id, password, passphrase, ...size });
        renderContent();
      } catch (error) {
        state.terminal.writeln(`\r\n\x1b[31m${String(error)}\x1b[0m`);
        showError(error);
      }
    }
  });
}

function usersView(content) {
  content.innerHTML = `
    <div class="section-head"><div><h2>SSH‑пользователи</h2><p>Создайте отдельную учётную запись для входа с другого ПК.</p></div></div>
    <article class="panel narrow"><form id="user-form" class="form-grid">
      ${field("Имя пользователя", "new-username", "text", "", true, "operator")}
	  ${field("Passphrase ключа администратора (если нужен)", "user-passphrase", "password")}
      <label class="full"><span>Публичный Ed25519‑ключ</span><textarea id="new-public-key" rows="5" required placeholder="ssh-ed25519 AAAA… admin-pc"></textarea><small>Закрытый ключ должен остаться на другом ПК.</small></label>
      <label class="toggle full"><input type="checkbox" id="new-sudo"><span></span><div><strong>Разрешить sudo</strong><small>Пользователь сможет выполнять административные команды.</small></div></label>
      <div class="full button-row end"><button type="submit" class="primary">Создать пользователя</button></div>
    </form></article>
    <div class="notice">bastionctl не создаёт и не копирует закрытые ключи пользователей. Перед созданием сгенерируйте ключ на втором ПК и вставьте только строку из файла <code>.pub</code>.</div>`;
  document.querySelector("#user-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    setBusy(true, "Создаём пользователя…");
    try {
      const result = await call("CreateUser", { server_id: state.selected, username: value("new-username"), public_key: value("new-public-key"), grant_sudo: checked("new-sudo"), passphrase: value("user-passphrase") });
      state.operation = result;
      toast("Пользователь создан", "success");
      event.target.reset();
    } catch (error) { showError(error); } finally { setBusy(false); }
  });
}

async function servicesView(content, server) {
  content.innerHTML = '<div class="loading-card">Загружаем конфигурацию сервисов…</div>';
  try {
    const view = await call("XHTTP", server.id);
    if (state.tab !== "services" || state.selected !== server.id) return;
    const config = view.config || {};
    content.innerHTML = `<div class="section-head"><div><h2>VLESS + TLS + XHTTP</h2><p>Закреплённый 3x-ui, loopback‑панель и сертификат Let's Encrypt</p></div></div>
      <div class="grid two service-layout"><article class="panel"><div class="panel-title"><div><h3>Желаемая конфигурация</h3><p>Здесь нет паролей, UUID и приватных ключей.</p></div></div>
        <form id="xhttp-form" class="form-grid">
          ${field("Домен", "x-domain", "text", config.domain || "", true, "vpn.example.com")}
          ${field("Email Let's Encrypt", "x-email", "email", config.email || "", true, "admin@example.com")}
          ${field("Публичный IPv4", "x-ip", "text", config.server_ip || "", true, "203.0.113.10")}
          ${field("Локальный порт панели (0 = случайный)", "x-port", "number", config.panel_port || 0, true)}
          ${config.web_base_path ? `<div class="notice full">Панель: <code>127.0.0.1:${config.panel_port}/${esc(config.web_base_path)}/</code></div>` : ""}
          <div class="full button-row end"><button type="submit" class="primary">${view.configured ? "Обновить конфигурацию" : "Создать конфигурацию"}</button></div>
        </form></article>
        <article class="panel"><div class="panel-title"><div><h3>Порядок запуска</h3><p>Автоматические и ручные этапы разделены.</p></div></div>
          ${view.configured ? `<label><span>Passphrase ключа, если нужен</span><input id="x-passphrase" type="password"></label><div class="service-actions"><button class="secondary" data-xaction="plan">План</button><button class="primary" data-xaction="apply">Установить</button><button class="secondary" data-xaction="verify">Проверить</button></div>` : '<div class="empty-result">Сначала сохраните домен, email и публичный IP.</div>'}
        </article></div>
      ${view.configured ? `<article class="panel guide-panel"><div class="panel-title"><div><h3>Что нужно сделать самостоятельно</h3><p>Приложение не покупает домен, не меняет firewall провайдера и не создаёт клиентский UUID.</p></div></div><div class="guide-steps">${(view.guide || []).map((step, index) => `<section><span>${index + 1}</span><div><h4>${esc(step.title)}</h4><ul>${step.details.map((detail) => `<li>${esc(detail)}</li>`).join("")}</ul></div></section>`).join("")}</div></article>
      <article class="panel report-panel"><div class="panel-title"><div><h3>Результат сервиса</h3><p id="report-caption">Выберите plan, apply или verify</p></div></div><div id="report"><div class="empty-result">Отчёт появится здесь</div></div></article>` : ""}`;
    document.querySelector("#xhttp-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      setBusy(true, "Сохраняем конфигурацию сервиса…");
      try {
        await call("ConfigureXHTTP", { server_id: server.id, domain: value("x-domain"), email: value("x-email"), server_ip: value("x-ip"), panel_port: Number(value("x-port")) });
        toast("Конфигурация сохранена. Сначала проверьте обычный plan безопасности.", "success");
        servicesView(content, server);
      } catch (error) { showError(error); } finally { setBusy(false); }
    });
    content.querySelectorAll("[data-xaction]").forEach((button) => button.addEventListener("click", () => runXHTTP(button.dataset.xaction)));
    if (state.operation?.report?.action?.startsWith("workload-xhttp")) renderReport(state.operation);
  } catch (error) { showError(error); }
}

async function runXHTTP(action) {
  const server = selectedServer();
  if (!server) return;
  let confirmation = "";
  if (action === "apply") {
    confirmation = await confirmText({ title: "Установить XHTTP workload", text: `Сначала должен быть проверен обычный план безопасности с TCP 80/443. Введите XHTTP APPLY ${server.id}.`, expected: `XHTTP APPLY ${server.id}`, dangerous: false });
    if (!confirmation) return;
  }
  setBusy(true, "Выполняется XHTTP‑операция…");
  try {
    state.operation = await call("RunXHTTP", { server_id: server.id, action, confirmation, passphrase: value("x-passphrase") });
    renderReport(state.operation);
    toast("Операция сервиса завершена", state.operation.report?.summary?.fail ? "warning" : "success");
  } catch (error) { showError(error); } finally { setBusy(false); }
}

async function historyView(content, server) {
  content.innerHTML = '<div class="loading-card">Загружаем историю…</div>';
  try {
    const history = await call("History", server.id, 100);
    if (state.tab !== "history" || state.selected !== server.id) return;
    content.innerHTML = `<div class="section-head"><div><h2>История операций</h2><p>Локальные отчёты для ${esc(server.name)}</p></div><button class="secondary" id="snapshot">Снять snapshot</button></div>
      <article class="panel"><div class="timeline">${history.length ? history.map((entry) => `<div class="timeline-item"><span class="status-dot ${entry.has_failures ? "danger" : "ok"}"></span><div><strong>${esc(entry.action)}</strong><small>${new Date(entry.timestamp).toLocaleString("ru-RU")}</small></div><code>${esc(entry.path.split(/[\\/]/).pop())}</code></div>`).join("") : '<div class="empty-result">История пока пуста</div>'}</div></article>`;
    document.querySelector("#snapshot").addEventListener("click", () => captureSnapshot(server));
  } catch (error) { showError(error); }
}

async function settingsView(content, server) {
  content.innerHTML = '<div class="loading-card">Загружаем политику…</div>';
  try {
    const settings = await call("SecuritySettings", server.id);
    if (state.tab !== "settings" || state.selected !== server.id) return;
    content.innerHTML = `<div class="section-head"><div><h2>Настройки политики</h2><p>Изменения сохраняются локально. Сервер меняется только после Plan → Apply.</p></div></div>
      <form id="settings-form" class="settings-layout">
        <article class="panel"><div class="panel-title"><div><h3>Профиль и модули</h3><p>Какие подсистемы контролирует bastionctl</p></div></div>
          <div class="profile-picker"><label><span>Профиль</span><select id="s-profile">${state.meta.profiles.map((name) => `<option ${name === settings.profile ? "selected" : ""}>${esc(name)}</option>`).join("")}</select></label><button type="button" class="secondary" id="apply-profile">Загрузить значения</button></div>
          <div class="toggle-grid">${toggle("SSH", "s-ssh", settings.manage_ssh)}${toggle("UFW firewall", "s-firewall", settings.manage_firewall)}${toggle("Fail2ban", "s-fail2ban", settings.manage_fail2ban)}${toggle("Автообновления", "s-updates", settings.manage_automatic_updates)}${toggle("auditd", "s-auditd", settings.manage_auditd)}${toggle("AppArmor", "s-apparmor", settings.manage_apparmor)}${toggle("Синхронизация времени", "s-time", settings.manage_time_sync)}</div>
        </article>
        <article class="panel"><div class="panel-title"><div><h3>Сеть и SSH</h3><p>Доступы, которые останутся после firewall</p></div></div>
          ${area("Разрешённые CIDR для SSH", "s-cidrs", settings.ssh_allowed_cidrs, "203.0.113.4/32")}
          <div class="form-grid">${field("TCP‑порты", "s-tcp", "text", settings.allowed_tcp_ports, false, "80, 443")}${field("UDP‑порты", "s-udp", "text", settings.allowed_udp_ports, false, "51820")}</div>
          <div class="toggle-grid danger-toggles">${toggle("Разрешить парольный SSH", "s-password", settings.password_authentication)}${toggle("Разрешить root SSH", "s-root", settings.permit_root_login)}</div>
        </article>
        <article class="panel"><div class="panel-title"><div><h3>Обновления и backup</h3><p>Контроль восстановления и перезагрузок</p></div></div>
          ${toggle("Автоматическая перезагрузка", "s-reboot", settings.automatic_reboot)}
          ${field("Время перезагрузки", "s-reboot-time", "time", settings.automatic_reboot_time)}
          ${area("Backup markers", "s-markers", settings.backup_markers, "/var/backups/app/latest.ok")}
          ${field("Максимальный возраст backup, часов", "s-backup-age", "number", settings.backup_max_age_hours)}
          ${toggle("Backup обязателен", "s-backup-required", settings.backup_required)}
        </article>
        <div class="sticky-actions"><span>После сохранения откройте «Защита» и выполните план.</span><button type="submit" class="primary">Сохранить политику</button></div>
      </form>
      <article class="panel connection-settings"><div class="panel-title"><div><h3>Подключение и локальная запись</h3><p>Изменение адреса не меняет сервер, но потребует новой сверки fingerprint.</p></div></div><form id="server-form" class="form-grid">
        ${field("Название", "server-name", "text", server.name, true)}${field("SSH‑цель", "server-target", "text", server.target, true)}
        ${field("SSH‑порт", "server-port", "number", server.port, true)}${field("Закрытый ключ", "server-identity", "text", server.identity || "")}
        ${field("Ubuntu‑бинарник для установки", "server-binary", "text", server.server_binary || "")}
        <div class="full button-row end"><button type="submit" class="secondary">Сохранить подключение</button><button type="button" class="danger-button" id="remove-server">Удалить запись</button></div>
      </form></article>`;
    document.querySelector("#settings-form").addEventListener("submit", (event) => saveSettings(event, server));
	document.querySelector("#apply-profile").addEventListener("click", () => {
	  const name = value("s-profile");
	  modal({
	    title: `Загрузить профиль ${name}`,
	    body: "<div class=\"notice warning\">Поля политики в этой форме будут заменены значениями выбранного профиля. Сервер не изменится, пока вы отдельно не выполните Plan → Apply.</div>",
	    submit: "Загрузить профиль",
	    onSubmit: async () => {
	      closeModal(); setBusy(true, "Загружаем профиль…");
	      try { await call("ApplyProfile", server.id, name); await refresh(false); await settingsView(content, selectedServer()); toast(`Профиль ${name} загружен`, "success"); }
	      catch (error) { showError(error); }
	      finally { setBusy(false); }
	    }
	  });
	});
	document.querySelector("#server-form").addEventListener("submit", async (event) => {
	  event.preventDefault();
	  setBusy(true, "Сохраняем подключение…");
	  try {
	    await call("UpdateServer", { id: server.id, name: value("server-name"), target: value("server-target"), port: Number(value("server-port")), identity: value("server-identity"), server_binary: value("server-binary") });
	    await refresh(false); render(); toast("Подключение сохранено", "success");
	  } catch (error) { showError(error); } finally { setBusy(false); }
	});
	document.querySelector("#remove-server").addEventListener("click", async () => {
	  const confirmation = await confirmText({ title: "Удалить запись сервера", text: `Будет удалена запись из реестра. Настройки и файлы на Ubuntu не изменятся. Введите REMOVE ${server.id}.`, expected: `REMOVE ${server.id}`, dangerous: true });
	  if (!confirmation) return;
	  try { await call("RemoveServer", server.id, confirmation); state.selected = ""; await refresh(); toast("Запись сервера удалена", "success"); } catch (error) { showError(error); }
	});
  } catch (error) { showError(error); }
}

async function saveSettings(event, server) {
  event.preventDefault();
  const settings = {
    profile: value("s-profile"), manage_ssh: checked("s-ssh"), manage_firewall: checked("s-firewall"),
    manage_fail2ban: checked("s-fail2ban"), manage_automatic_updates: checked("s-updates"),
    manage_auditd: checked("s-auditd"), manage_apparmor: checked("s-apparmor"), manage_time_sync: checked("s-time"),
    password_authentication: checked("s-password"), permit_root_login: checked("s-root"),
    ssh_allowed_cidrs: value("s-cidrs"), allowed_tcp_ports: value("s-tcp"), allowed_udp_ports: value("s-udp"),
    automatic_reboot: checked("s-reboot"), automatic_reboot_time: value("s-reboot-time"),
    backup_markers: value("s-markers"), backup_max_age_hours: Number(value("s-backup-age")), backup_required: checked("s-backup-required")
  };
  setBusy(true, "Сохраняем политику…");
  try {
    await call("SaveSecuritySettings", server.id, settings);
    await refresh(false);
    toast("Политика сохранена. Теперь проверьте план.", "success");
  } catch (error) { showError(error); } finally { setBusy(false); }
}

async function hostKeyFlow(server) {
  setBusy(true, "Получаем fingerprint…");
  try {
    const info = await call("ProbeHostKey", server.id);
    state.fingerprint = info;
    if (info.changed) {
      return modal({ title: "SSH host key изменился", dangerous: true, body: `<div class="notice danger">Закреплённый ключ не совпадает с ключом сервера. Не продолжайте, пока через rescue‑консоль или панель провайдера не подтвердите, что сервер действительно был переустановлен.</div><div class="fingerprint"><span>Новый fingerprint</span><code>${esc(info.fingerprint)}</code></div>${field(`Введите REPLACE ${info.fingerprint}`, "replace-confirm", "text", "", true)}`, submit: "Заменить закреплённый ключ", onSubmit: async () => {
		try {
		  await call("ReplaceHostKey", server.id, info.fingerprint, value("replace-confirm"));
		  closeModal(); await refresh(false); render(); toast("Host key заменён; предыдущая запись сохранена", "success");
		} catch (error) { showError(error); }
	  }});
    }
    if (info.trusted) {
      toast("Fingerprint совпадает с закреплённым", "success");
      return;
    }
    modal({
      title: "Сверьте SSH fingerprint",
      body: `<div class="notice warning">Откройте rescue/serial console у провайдера и выполните <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>. Не подтверждайте fingerprint только по данным из этого окна.</div><div class="fingerprint"><span>${esc(info.algorithm)}</span><code>${esc(info.fingerprint)}</code></div>${field(`Введите TRUST ${info.fingerprint}`, "trust-confirm", "text", "", true)}`,
      submit: "Закрепить ключ",
      onSubmit: async () => {
        try {
          await call("TrustHostKey", server.id, info.fingerprint, value("trust-confirm"));
          closeModal();
          await refresh(false);
          toast("SSH fingerprint закреплён", "success");
        } catch (error) { showError(error); }
      }
    });
  } catch (error) { showError(error); } finally { setBusy(false); }
}

async function installServer(server) {
  if (server.bootstrap_pending) return openConnect(server, true);
  if (!server.host_key_trusted) return hostKeyFlow(server);
  modal({
    title: "Установить серверный компонент",
    body: `<div class="notice">Файлы будут загружены во временные пути, проверены по SHA‑256 и установлены с автоматическим откатом. В консоли введите sudo‑пароль администратора, когда его запросит Ubuntu.</div>${field("Пароль SSH‑ключа (если нужен)", "install-passphrase", "password")}`,
    submit: "Загрузить и открыть консоль",
    onSubmit: async () => {
      const passphrase = value("install-passphrase");
      closeModal();
      state.tab = "terminal";
      render();
      ensureTerminal();
      setBusy(true, "Проверяем архитектуру и загружаем файлы…");
      try {
        state.session = await call("StartInstall", {
          server_id: server.id, binary_path: "", passphrase,
          columns: state.terminal.cols || 100, rows: state.terminal.rows || 30
        });
        state.terminal.writeln("\r\n\x1b[36mФайлы загружены. При запросе [sudo] password введите пароль администратора.\x1b[0m");
        renderContent();
      } catch (error) { showError(error); } finally { setBusy(false); }
    }
  });
}

async function captureSnapshot(server) {
  modal({
	title: "Снять snapshot сервера",
	body: `${field("Пароль SSH‑ключа (если нужен)", "snapshot-passphrase", "password")}<div class="notice">Passphrase используется только для этого подключения и не сохраняется.</div>`,
	submit: "Снять snapshot",
	onSubmit: async () => {
	  const passphrase = value("snapshot-passphrase");
	  closeModal(); setBusy(true, "Снимаем snapshot…");
	  try {
		const result = await call("CaptureSnapshot", { server_id: server.id, force_baseline: false, passphrase });
		toast(result.baseline_created ? "Создан первый baseline" : result.diff?.changes?.length ? `Обнаружено изменений: ${result.diff.changes.length}` : "Изменений нет", result.diff?.changes?.length ? "warning" : "success");
		renderContent();
	  } catch (error) { showError(error); } finally { setBusy(false); }
	}
  });
}

function openAddServer() {
  const profiles = state.meta?.profiles || ["minimal"];
  modal({
    title: "Добавить Ubuntu‑сервер",
    wide: true,
    body: `<form id="add-form" class="form-grid">
      ${field("ID сервера", "add-id", "text", "", true, "prod-1")}${field("Название", "add-name", "text", "", true, "Production")}
      ${field("IP или hostname", "add-host", "text", "", true, "203.0.113.10")}${field("SSH‑порт", "add-port", "number", "22", true)}
      ${field("Пользователь первого входа", "add-user", "text", "root", true)}<label><span>Профиль</span><select id="add-profile">${profiles.map((item) => `<option>${esc(item)}</option>`).join("")}</select></label>
      <label class="toggle full"><input type="checkbox" id="add-bootstrap" checked><span></span><div><strong>Первый вход по паролю</strong><small>Пароль будет запрошен после безопасной сверки fingerprint.</small></div></label>
      ${field("Постоянный администратор", "add-admin-user", "text", "bastion", false, "bastion")}
      ${field("Существующий закрытый ключ", "add-identity", "text", "", false, "C:\\Users\\…\\.ssh\\id_ed25519")}
      ${area("Разрешённые CIDR для SSH", "add-cidrs", "", "198.51.100.24/32")}
      <div class="notice full">Перед подключением откройте консоль провайдера: она потребуется для независимой сверки fingerprint и как аварийный доступ.</div>
    </form>`,
    submit: "Добавить",
    onSubmit: async () => {
      const host = value("add-host").trim();
      const user = value("add-user").trim();
      const bootstrap = checked("add-bootstrap");
      try {
        const created = await call("AddServer", {
          id: value("add-id"), name: value("add-name"), target: `${user}@${host}`,
          port: Number(value("add-port")), identity: value("add-identity"), profile: value("add-profile"),
          ssh_allowed_cidrs: value("add-cidrs").split(/[\n,;]/).map((item) => item.trim()).filter(Boolean),
          server_binary: "", password_bootstrap: bootstrap, bootstrap_admin_user: bootstrap ? value("add-admin-user") : ""
        });
        closeModal();
        await refresh(false);
        selectServer(created.id);
        toast("Сервер добавлен. Теперь сверьте fingerprint.", "success");
      } catch (error) { showError(error); }
    }
  });
  document.querySelector("#add-bootstrap").addEventListener("change", (event) => {
    document.querySelector("#add-admin-user").disabled = !event.target.checked;
  });
}

function field(label, id, type = "text", current = "", required = false, placeholder = "") {
  return `<label><span>${esc(label)}</span><input id="${id}" type="${type}" value="${esc(current)}" placeholder="${esc(placeholder)}" ${required ? "required" : ""}></label>`;
}

function area(label, id, current = "", placeholder = "") {
  return `<label class="full"><span>${esc(label)}</span><textarea id="${id}" rows="3" placeholder="${esc(placeholder)}">${esc(current)}</textarea></label>`;
}

function toggle(label, id, enabled) {
  return `<label class="toggle"><input type="checkbox" id="${id}" ${enabled ? "checked" : ""}><span></span><div><strong>${esc(label)}</strong></div></label>`;
}

function value(id) { return document.querySelector(`#${id}`)?.value || ""; }
function checked(id) { return Boolean(document.querySelector(`#${id}`)?.checked); }

function modal({ title, body, submit, onSubmit, dangerous = false, wide = false }) {
  const layer = document.querySelector("#modal-layer");
  layer.innerHTML = `<div class="modal-backdrop"><section class="modal ${wide ? "wide" : ""}" role="dialog" aria-modal="true"><header><h2>${esc(title)}</h2><button class="modal-close" aria-label="Закрыть">×</button></header><div class="modal-body">${body}</div><footer><button class="secondary modal-cancel">Отмена</button><button class="${dangerous ? "danger-button" : "primary"} modal-submit">${esc(submit)}</button></footer></section></div>`;
  layer.querySelector(".modal-close").addEventListener("click", closeModal);
  layer.querySelector(".modal-cancel").addEventListener("click", closeModal);
  layer.querySelector(".modal-submit").addEventListener("click", onSubmit);
  layer.querySelector(".modal-backdrop").addEventListener("mousedown", (event) => { if (event.target === event.currentTarget) closeModal(); });
  layer.querySelector("input, textarea, select")?.focus();
}

function closeModal() { document.querySelector("#modal-layer").innerHTML = ""; }

function confirmText({ title, text, expected, dangerous }) {
  return new Promise((resolve) => {
    modal({ title, dangerous, body: `<div class="notice ${dangerous ? "danger" : "warning"}">${esc(text)}</div>${field(expected, "exact-confirm", "text", "", true)}`, submit: "Подтвердить", onSubmit: () => {
      const result = value("exact-confirm");
      if (result !== expected) return showError(`Ожидается точная строка: ${expected}`);
      closeModal();
      resolve(result);
    }});
    document.querySelector(".modal-cancel").addEventListener("click", () => resolve(""), { once: true });
    document.querySelector(".modal-close").addEventListener("click", () => resolve(""), { once: true });
  });
}

function setBusy(enabled, text = "Выполняется…") {
  state.busy = enabled;
  let overlay = document.querySelector("#busy-overlay");
  if (enabled) {
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = "busy-overlay";
      overlay.className = "busy-overlay";
      document.body.append(overlay);
    }
    overlay.innerHTML = `<span class="spinner"></span><strong>${esc(text)}</strong>`;
  } else overlay?.remove();
}

function toast(message, type = "info") {
  const item = document.createElement("div");
  item.className = `toast ${type}`;
  item.textContent = message;
  document.querySelector("#toasts").append(item);
  setTimeout(() => item.remove(), 5000);
}

function showError(error) {
  const message = typeof error === "string" ? error : error?.message || String(error);
  toast(message.replace(/^Error:\s*/, ""), "error");
}

async function auditAll() {
	if (!state.servers.length) return;
	setBusy(true, "Проверяем все серверы…");
	try {
	  const results = await call("AuditAll");
	  const failed = results.filter((item) => item.error || item.operation?.report?.summary?.fail).length;
	  await refresh(false); render();
	  toast(failed ? `Аудит завершён: проблемных серверов ${failed}` : `Аудит завершён: ${results.length} серверов без ошибок`, failed ? "warning" : "success");
	} catch (error) { showError(error); } finally { setBusy(false); }
}

async function refresh(renderAfter = true) {
  try {
    state.meta = await call("InitialState");
    state.servers = state.meta.servers || [];
    document.querySelector("#version").textContent = `v${state.meta.version} · ${state.meta.platform}`;
    if (!state.selected || !state.servers.some((item) => item.id === state.selected)) state.selected = state.servers[0]?.id || "";
    if (renderAfter) render();
  } catch (error) { showError(error); }
}

function selectServer(id) {
  if (state.session && id !== state.selected) {
    toast("Сначала отключите активную консоль", "warning");
    return;
  }
  state.selected = id;
  state.operation = null;
  state.tab = "overview";
  render();
}

function bindEvents() {
  const events = window.runtime;
  if (!events?.EventsOn) return;
  events.EventsOn("terminal:event", (event) => {
    if (event.session_id !== state.session && state.session) return;
	if (event.kind === "data") {
	  if (event.encoding === "base64") {
	    const raw = atob(event.data || "");
	    const bytes = Uint8Array.from(raw, (char) => char.charCodeAt(0));
	    state.terminal?.write(state.terminalDecoder.decode(bytes, { stream: true }));
	  } else state.terminal?.write(event.data || "");
	}
    if (event.kind === "connected") {
      if (!state.session) state.session = event.session_id;
      state.terminal?.writeln("\r\n\x1b[32mSSH подключён\x1b[0m");
    }
    if (event.kind === "closed") {
	  const tail = state.terminalDecoder.decode();
	  if (tail) state.terminal?.write(tail);
	  state.terminalDecoder = new TextDecoder();
      state.terminal?.writeln(`\r\n\x1b[90mSSH отключён${event.error ? `: ${event.error}` : ""}\x1b[0m`);
      state.session = "";
      if (state.tab === "terminal") renderContent();
    }
  });
  events.EventsOn("bootstrap:completed", async () => {
    await refresh(false);
    toast("Первичный вход завершён, ключ проверен", "success");
    render();
  });
  events.EventsOn("bootstrap:failed", (event) => {
    toast(`Первичный вход не завершён: ${event.error}`, "error");
  });
  events.EventsOn("install:completed", async (operation) => {
    state.operation = operation;
    await refresh(false);
    toast("Серверный компонент установлен и проверен", "success");
    render();
  });
  events.EventsOn("install:failed", async (event) => {
    if (event.operation) state.operation = event.operation;
    await refresh(false);
    toast(`Установка не завершена: ${event.error}`, "error");
    render();
  });
}

async function start() {
  shell();
  bindEvents();
  await refresh();
}

start();
