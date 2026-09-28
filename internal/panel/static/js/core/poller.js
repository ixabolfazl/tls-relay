/**
 * Robust polling helper that pauses on document visibility change
 * and prevents overlapping async invocations.
 */

export class Poller {
  constructor(fn, intervalMs, { immediate = true, jitterMs = 0 } = {}) {
    this.fn = fn;
    this.intervalMs = intervalMs;
    this.immediate = immediate;
    this.jitterMs = jitterMs;
    this.timer = null;
    this.running = false;
    this.inFlight = false;
    this.boundVisibilityHandler = this.handleVisibilityChange.bind(this);
  }

  start() {
    if (this.running) return;
    this.running = true;
    document.addEventListener('visibilitychange', this.boundVisibilityHandler);

    if (this.immediate && !document.hidden) {
      this.tick();
    } else {
      this.scheduleNext();
    }
  }

  stop() {
    this.running = false;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    document.removeEventListener('visibilitychange', this.boundVisibilityHandler);
  }

  handleVisibilityChange() {
    if (!this.running) return;
    if (!document.hidden) {
      // User returned to tab -> trigger immediately
      this.tick();
    } else if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  scheduleNext() {
    if (!this.running || document.hidden) return;
    if (this.timer) clearTimeout(this.timer);

    const jitter = this.jitterMs > 0 ? (Math.random() - 0.5) * this.jitterMs : 0;
    const delay = Math.max(500, this.intervalMs + jitter);

    this.timer = setTimeout(() => this.tick(), delay);
  }

  async tick() {
    if (!this.running || document.hidden || this.inFlight) return;
    this.inFlight = true;
    try {
      await this.fn();
    } catch (err) {
      // Let caller handle or log without breaking the poller
      console.warn('Poller tick error:', err);
    } finally {
      this.inFlight = false;
      if (this.running && !document.hidden) {
        this.scheduleNext();
      }
    }
  }

  async trigger() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    await this.tick();
  }
}
