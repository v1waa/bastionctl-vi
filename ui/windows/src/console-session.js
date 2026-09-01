// Wails can deliver connected/closed events before the start call resolves.
// Keep late replies and events from a finished session out of the next one.
export class ConsoleSession {
  id = "";
  serverId = "";
  starting = false;
  retired = new Set();
  generation = 0;

  get busy() { return this.starting || Boolean(this.id); }

  begin(serverId) {
    if (this.busy) throw new Error("Сначала отключите активную консоль");
    this.serverId = serverId;
    this.starting = true;
    return ++this.generation;
  }

  accept(event) {
    const id = event.session_id;
    if (!id || event.server_id !== this.serverId || this.retired.has(id)) return false;
    if (event.kind === "connected" && this.starting && !this.id) this.id = id;
    return this.id === id;
  }

  started(id, generation = this.generation) {
    if (generation !== this.generation) return;
    if (!this.retired.has(id)) this.id = id;
    this.starting = false;
    if (!this.id) this.serverId = "";
  }

  failed(generation) {
    if (generation === this.generation) this.end(this.id);
  }

  end(id) {
    if (id) {
      this.retired.add(id);
      if (this.retired.size > 32) this.retired.delete(this.retired.values().next().value);
    }
    if (!id || this.id === id) {
      this.id = "";
      this.serverId = "";
      this.starting = false;
    }
  }
}
