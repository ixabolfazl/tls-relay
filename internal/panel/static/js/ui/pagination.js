/**
 * Accessible numeric pagination component.
 *
 * @param {HTMLElement|string} container - Target container element or selector.
 * @param {object} options
 * @param {number} options.currentPage - Current 1-based page index.
 * @param {number} options.totalPages - Total number of pages.
 * @param {number} options.totalItems - Total item count.
 * @param {number} [options.pageSize=50] - Number of items per page.
 * @param {function(number): void} options.onPageChange - Callback when a page is selected.
 */
export function renderPagination(
  container,
  { currentPage = 1, totalPages = 1, totalItems = 0, pageSize = 50, onPageChange }
) {
  const el = typeof container === 'string' ? document.querySelector(container) : container;
  if (!el) return;

  const validTotalPages = Math.max(1, parseInt(totalPages, 10) || 1);
  const validPage = Math.min(Math.max(1, parseInt(currentPage, 10) || 1), validTotalPages);
  const validTotalItems = Math.max(0, parseInt(totalItems, 10) || 0);
  const validPageSize = Math.max(1, parseInt(pageSize, 10) || 50);

  const start = validTotalItems > 0 ? (validPage - 1) * validPageSize + 1 : 0;
  const end = validTotalItems > 0 ? Math.min(validPage * validPageSize, validTotalItems) : 0;
  const infoText =
    validTotalItems > 0 ? `Showing ${start}–${end} of ${validTotalItems}` : 'Showing 0 of 0';

  const pageItems = calculatePageItems(validPage, validTotalPages);

  // Clear previous content
  el.innerHTML = '';

  // Info label
  const infoEl = document.createElement('div');
  infoEl.className = 'text-xs text-txt-muted';
  infoEl.textContent = infoText;
  el.appendChild(infoEl);

  // Controls container
  const nav = document.createElement('nav');
  nav.className = 'flex items-center gap-1.5 flex-wrap';
  nav.setAttribute('aria-label', 'Pagination');

  // Prev button
  const prevBtn = document.createElement('button');
  prevBtn.type = 'button';
  prevBtn.className = 'btn btn-secondary btn-sm';
  prevBtn.textContent = 'Previous';
  prevBtn.setAttribute('aria-label', 'Previous page');
  if (validPage <= 1) {
    prevBtn.disabled = true;
  } else {
    prevBtn.addEventListener('click', () => {
      if (typeof onPageChange === 'function') {
        onPageChange(validPage - 1);
      }
    });
  }
  nav.appendChild(prevBtn);

  // Number / ellipsis items
  for (const item of pageItems) {
    if (item === '…') {
      const ellipsis = document.createElement('span');
      ellipsis.className = 'px-1.5 py-1 text-xs text-txt-muted select-none';
      ellipsis.setAttribute('aria-hidden', 'true');
      ellipsis.textContent = '…';
      nav.appendChild(ellipsis);
    } else {
      const pageNum = item;
      const isCurrent = pageNum === validPage;
      const pageBtn = document.createElement('button');
      pageBtn.type = 'button';
      pageBtn.className = isCurrent ? 'btn btn-primary btn-sm' : 'btn btn-secondary btn-sm';
      pageBtn.textContent = String(pageNum);
      pageBtn.setAttribute('aria-label', `Page ${pageNum}`);
      if (isCurrent) {
        pageBtn.setAttribute('aria-current', 'page');
      } else {
        pageBtn.addEventListener('click', () => {
          if (typeof onPageChange === 'function') {
            onPageChange(pageNum);
          }
        });
      }
      nav.appendChild(pageBtn);
    }
  }

  // Next button
  const nextBtn = document.createElement('button');
  nextBtn.type = 'button';
  nextBtn.className = 'btn btn-secondary btn-sm';
  nextBtn.textContent = 'Next';
  nextBtn.setAttribute('aria-label', 'Next page');
  if (validPage >= validTotalPages) {
    nextBtn.disabled = true;
  } else {
    nextBtn.addEventListener('click', () => {
      if (typeof onPageChange === 'function') {
        onPageChange(validPage + 1);
      }
    });
  }
  nav.appendChild(nextBtn);

  el.appendChild(nav);
}

function calculatePageItems(currentPage, totalPages) {
  if (totalPages <= 7) {
    const pages = [];
    for (let i = 1; i <= totalPages; i++) {
      pages.push(i);
    }
    return pages;
  }

  const pages = [1];
  const delta = 2;
  const start = Math.max(2, currentPage - delta);
  const end = Math.min(totalPages - 1, currentPage + delta);

  if (start > 2) {
    pages.push('…');
  }

  for (let i = start; i <= end; i++) {
    pages.push(i);
  }

  if (end < totalPages - 1) {
    pages.push('…');
  }

  pages.push(totalPages);
  return pages;
}
