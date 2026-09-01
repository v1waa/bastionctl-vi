export const managementTabs = [
  ["overview", "Обзор"],
  ["security", "Защита"],
  ["users", "Пользователи"],
  ["services", "Сервисы"],
  ["history", "История"],
  ["settings", "Настройки"]
];

// The single translucent layer is .terminal-surface in CSS, not the text or
// the xterm canvas. Stacking translucent backgrounds would change the opacity.
export const terminalOptions = {
  allowTransparency: true,
  cursorBlink: true,
  convertEol: false,
  fontFamily: '"Cascadia Mono", Consolas, monospace',
  fontSize: 14,
  lineHeight: 1.25,
  scrollback: 6000,
  theme: {
    background: "#00000000",
    foreground: "#eeeeee",
    cursor: "#eeeeee",
    selectionBackground: "#626262"
  }
};

export const shellMarkup = `
  <div class="shell">
    <aside class="sidebar" aria-label="Серверы">
      <div class="sidebar-heading"><h1>Серверы</h1><button class="secondary" id="add-server">Добавить</button></div>
      <div class="server-list" id="server-list"></div>
      <div class="sidebar-footer" id="version"></div>
    </aside>
    <main class="workspace" aria-label="Консоль сервера">
      <header class="topbar" id="topbar"></header>
      <section class="terminal-surface" aria-label="SSH-консоль">
        <div id="terminal-empty" class="terminal-empty">Добавьте сервер слева, чтобы открыть его консоль.</div>
        <div id="terminal-host" class="terminal-host" hidden></div>
      </section>
      <footer class="terminal-note">Команды выполняются на выбранном сервере. Ввод и вывод консоли не сохраняются.</footer>
    </main>
  </div>
  <dialog id="management-dialog" class="management-dialog" aria-labelledby="management-title">
    <header class="management-header"><h2 id="management-title">Управление сервером</h2><div class="button-row"><button class="secondary" id="refresh">Обновить</button><button class="secondary" id="audit-all">Аудит всех</button><button class="secondary" id="management-close">Закрыть</button></div></header>
    <nav class="tabs" id="tabs" role="tablist" aria-label="Управление"></nav>
    <section class="content" id="content" role="tabpanel"></section>
  </dialog>
  <div class="modal-layer" id="modal-layer"></div>
  <div class="toasts" id="toasts" aria-live="polite"></div>`;
