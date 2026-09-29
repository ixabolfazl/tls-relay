/**
 * Minimal inline SVG sparkline helper.
 * Dependency-free, static polyline SVG.
 */

import { escapeHtml } from '../core/dom.js';

export function renderSparkline(container, values = [], {
  color = '#10b981',
  strokeWidth = 2,
} = {}) {
  if (!container) return;

  if (!values || values.length === 0) {
    container.innerHTML = `<span class="text-xs text-txt-subtle italic">No activity data</span>`;
    return;
  }

  const width = 200;
  const height = 36;
  const padding = strokeWidth + 2;
  const usableWidth = width - padding * 2;
  const usableHeight = height - padding * 2;

  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min;

  let points = '';
  if (values.length === 1 || range === 0) {
    const y = (height / 2).toFixed(1);
    points = `${padding},${y} ${width - padding},${y}`;
  } else {
    points = values
      .map((val, idx) => {
        const x = padding + (idx / (values.length - 1)) * usableWidth;
        const y = height - padding - ((val - min) / range) * usableHeight;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  }

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" class="w-full h-9" preserveAspectRatio="none" aria-hidden="true">
      <polyline
        fill="none"
        stroke="${escapeHtml(color)}"
        stroke-width="${strokeWidth}"
        stroke-linecap="round"
        stroke-linejoin="round"
        points="${points}"
      />
    </svg>
  `;
}
