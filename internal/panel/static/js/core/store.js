/**
 * Global reactive state store.
 */

class Store {
  constructor() {
    this.state = {
      authenticated: false,
      settings: null,
      currentRoute: 'dashboard',
    };
    this.listeners = new Set();
  }

  getState() {
    return this.state;
  }

  setState(partial) {
    this.state = { ...this.state, ...partial };
    this.notify();
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  notify() {
    for (const listener of this.listeners) {
      try {
        listener(this.state);
      } catch (e) {
        console.error('Store listener error:', e);
      }
    }
  }
}

export const store = new Store();
