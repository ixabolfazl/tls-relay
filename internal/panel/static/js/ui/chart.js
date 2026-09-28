/**
 * Responsive SVG chart component with proper scaling, axes, ticks, tooltips, and legend.
 * Fixes F15 (no preserveAspectRatio="none" text distortion, true dynamic sizing via ResizeObserver).
 */

import { escapeHtml } from '../core/dom.js';
import { formatBytes, formatCount } from '../core/format.js';

export function renderGroupedBarChart(container, {
  data = [], // [{ label, series1, series2, raw }]
  series = [
    { key: 'series1', label: 'Series 1', color: '#3b82f6' },
    { key: 'series2', label: 'Series 2', color: '#94a3b8' },
  ],
  formatValue = (v) => formatCount(v),
  emptyMessage = 'No request activity in this period',
} = {}) {
  if (!container) return { destroy: () => {} };

  container.innerHTML = '';
  container.className = 'relative w-full flex flex-col items-stretch';

  if (!data || data.length === 0) {
    container.innerHTML = `
      <div class="h-48 flex items-center justify-center text-xs text-txt-subtle italic border border-dashed border-border rounded-lg">
        ${emptyMessage}
      </div>
    `;
    return { destroy: () => {} };
  }

  // Legend header
  const legendEl = document.createElement('div');
  legendEl.className = 'flex items-center justify-end gap-4 mb-2 text-xs text-txt-muted';
  legendEl.innerHTML = series
    .map(
      (s) => `
      <div class="flex items-center gap-1.5">
        <span class="w-2.5 h-2.5 rounded-sm shrink-0" style="background-color: ${s.color}"></span>
        <span>${escapeHtml(s.label)}</span>
      </div>
    `
    )
    .join('');
  container.appendChild(legendEl);

  const chartWrapper = document.createElement('div');
  chartWrapper.className = 'relative w-full h-52 select-none';
  container.appendChild(chartWrapper);

  const tooltipEl = document.createElement('div');
  tooltipEl.className =
    'absolute pointer-events-none hidden bg-surface text-txt border border-border rounded-lg shadow-popover px-3 py-2 text-xs z-30 transition-transform duration-75';
  chartWrapper.appendChild(tooltipEl);

  function draw() {
    const width = chartWrapper.clientWidth || 400;
    const height = chartWrapper.clientHeight || 208;
    const padding = { top: 12, right: 16, bottom: 28, left: 48 };

    const plotWidth = Math.max(10, width - padding.left - padding.right);
    const plotHeight = Math.max(10, height - padding.top - padding.bottom);

    // Calculate max value
    let maxVal = 0;
    for (const d of data) {
      for (const s of series) {
        const v = Number(d[s.key]) || 0;
        if (v > maxVal) maxVal = v;
      }
    }
    if (maxVal === 0) maxVal = 10;
    // Round max up slightly for nice grid lines
    const yMax = Math.ceil(maxVal * 1.15);

    // Y ticks (4 levels)
    const yTicks = [0, Math.round(yMax * 0.33), Math.round(yMax * 0.66), yMax];

    let svg = `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" class="w-full h-full overflow-visible">`;

    // Horizontal grid lines and Y labels
    for (const tick of yTicks) {
      const y = padding.top + plotHeight - (tick / yMax) * plotHeight;
      svg += `
        <line x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}" stroke="currentColor" stroke-opacity="0.08" stroke-dasharray="3,3" />
        <text x="${padding.left - 8}" y="${y + 3}" fill="currentColor" class="text-[10px] text-txt-subtle fill-current" text-anchor="end">${escapeHtml(
        formatValue(tick)
      )}</text>
      `;
    }

    // Bars
    const groupCount = data.length;
    const groupWidth = plotWidth / groupCount;
    const barPadding = Math.max(2, groupWidth * 0.15);
    const availableBarWidth = (groupWidth - barPadding * 2) / series.length;
    const barWidth = Math.max(2, Math.min(availableBarWidth, 24));

    // Label step thinning for X axis
    const labelStep = Math.max(1, Math.ceil(groupCount / (width < 500 ? 5 : 10)));

    data.forEach((d, groupIdx) => {
      const groupX = padding.left + groupIdx * groupWidth;
      const groupCenterX = groupX + groupWidth / 2;

      // X label
      if (groupIdx % labelStep === 0 || groupIdx === groupCount - 1) {
        svg += `
          <text x="${groupCenterX}" y="${height - 8}" fill="currentColor" class="text-[10px] text-txt-subtle fill-current" text-anchor="middle">${escapeHtml(
          d.label
        )}</text>
        `;
      }

      // Series bars
      const totalBarsWidth = series.length * barWidth;
      const startX = groupCenterX - totalBarsWidth / 2;

      series.forEach((s, sIdx) => {
        const val = Number(d[s.key]) || 0;
        const barH = (val / yMax) * plotHeight;
        const barY = padding.top + plotHeight - barH;
        const barX = startX + sIdx * barWidth;

        svg += `
          <rect
            x="${barX}"
            y="${barY}"
            width="${Math.max(1, barWidth - 1)}"
            height="${Math.max(0, barH)}"
            fill="${s.color}"
            rx="2"
            class="transition-opacity hover:opacity-80 cursor-pointer"
            data-group-index="${groupIdx}"
            data-series-key="${s.key}"
          />
        `;
      });
    });

    svg += '</svg>';

    // Clear previous SVG
    const existingSvg = chartWrapper.querySelector('svg');
    if (existingSvg) existingSvg.remove();

    chartWrapper.insertAdjacentHTML('afterbegin', svg);

    // Wire tooltip on mousemove
    const svgEl = chartWrapper.querySelector('svg');
    if (svgEl) {
      svgEl.addEventListener('mousemove', (e) => {
        const rect = e.target.closest('rect[data-group-index]');
        if (!rect) {
          tooltipEl.classList.add('hidden');
          return;
        }

        const groupIdx = parseInt(rect.getAttribute('data-group-index'), 10);
        const item = data[groupIdx];
        if (!item) return;

        let content = `<div class="font-semibold text-txt mb-1">${escapeHtml(item.label)}</div>`;
        for (const s of series) {
          const val = item[s.key] || 0;
          content += `
            <div class="flex items-center justify-between gap-3 text-txt-muted py-0.5">
              <span class="flex items-center gap-1.5"><span class="w-2 h-2 rounded-full" style="background-color:${s.color}"></span>${escapeHtml(
            s.label
          )}:</span>
              <span class="font-medium text-txt">${escapeHtml(formatValue(val))}</span>
            </div>
          `;
        }

        tooltipEl.innerHTML = content;
        tooltipEl.classList.remove('hidden');

        const wrapperRect = chartWrapper.getBoundingClientRect();
        let tipX = e.clientX - wrapperRect.left + 12;
        let tipY = e.clientY - wrapperRect.top - 10;

        if (tipX + 160 > wrapperRect.width) {
          tipX = e.clientX - wrapperRect.left - 170;
        }

        tooltipEl.style.transform = `translate(${tipX}px, ${tipY}px)`;
      });

      svgEl.addEventListener('mouseleave', () => {
        tooltipEl.classList.add('hidden');
      });
    }
  }

  const resizeObserver = new ResizeObserver(() => {
    requestAnimationFrame(draw);
  });
  resizeObserver.observe(chartWrapper);

  draw();

  return {
    destroy: () => {
      resizeObserver.disconnect();
    },
  };
}
