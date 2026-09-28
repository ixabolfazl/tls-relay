/**
 * Formatting utilities for bytes, timestamps, durations, and numbers.
 */

import { store } from './store.js';

export function formatBytes(bytes) {
  if (bytes === undefined || bytes === null || isNaN(bytes)) return '0 B';
  const b = Number(bytes);
  if (b === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  const i = Math.floor(Math.log(Math.abs(b)) / Math.log(1024));
  const idx = Math.min(i, units.length - 1);
  const val = b / Math.pow(1024, idx);
  return `${val.toFixed(val >= 100 || idx === 0 ? 0 : val >= 10 ? 1 : 2)} ${units[idx]}`;
}

export function formatCount(num) {
  if (num === undefined || num === null || isNaN(num)) return '0';
  return Number(num).toLocaleString();
}

export function formatDuration(seconds) {
  if (!seconds || seconds <= 0) return '0s';
  const s = Math.floor(seconds);
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const secs = s % 60;

  if (days > 0) {
    return `${days}d ${hours}h ${mins}m`;
  }
  if (hours > 0) {
    return `${hours}h ${mins}m ${secs}s`;
  }
  if (mins > 0) {
    return `${mins}m ${secs}s`;
  }
  return `${secs}s`;
}

const formatterCache = new Map();

function getFormatter(options, tz) {
  const timezone = tz || store.getState().settings?.timezone || 'UTC';
  const key = JSON.stringify(options) + '|' + timezone;
  if (!formatterCache.has(key)) {
    try {
      formatterCache.set(key, new Intl.DateTimeFormat('en-US', { ...options, timeZone: timezone }));
    } catch {
      formatterCache.set(key, new Intl.DateTimeFormat('en-US', { ...options, timeZone: 'UTC' }));
    }
  }
  return formatterCache.get(key);
}

export function formatDate(dateInput, tz) {
  if (!dateInput) return '—';
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return '—';
  const fmt = getFormatter({ year: 'numeric', month: 'short', day: '2-digit' }, tz);
  return fmt.format(d);
}

export function formatTime(dateInput, tz) {
  if (!dateInput) return '—';
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return '—';
  const fmt = getFormatter({ hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }, tz);
  return fmt.format(d);
}

export function formatDateTime(dateInput, tz) {
  if (!dateInput) return '—';
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return '—';
  const fmt = getFormatter(
    {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    },
    tz
  );
  return fmt.format(d);
}

export function formatRelativeTime(dateInput) {
  if (!dateInput) return 'Never';
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return 'Never';
  const now = Date.now();
  const diffSec = Math.floor((now - d.getTime()) / 1000);

  if (diffSec < 5) return 'Just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  if (diffSec < 2592000) return `${Math.floor(diffSec / 86400)}d ago`;
  return formatDate(d);
}
