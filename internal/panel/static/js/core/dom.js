/**
 * Safe HTML template tag and DOM helpers with automatic XSS protection.
 */

const ESCAPE_MAP = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/[&<>"']/g, (c) => ESCAPE_MAP[c]);
}

class RawHtml {
  constructor(content) {
    this.content = String(content);
  }
  toString() {
    return this.content;
  }
}

export function raw(content) {
  if (content instanceof RawHtml) return content;
  return new RawHtml(content);
}

export function html(strings, ...values) {
  let result = '';
  for (let i = 0; i < strings.length; i++) {
    result += strings[i];
    if (i < values.length) {
      const val = values[i];
      if (val instanceof RawHtml) {
        result += val.content;
      } else if (Array.isArray(val)) {
        result += val
          .map((item) => (item instanceof RawHtml ? item.content : escapeHtml(item)))
          .join('');
      } else if (val === null || val === undefined) {
        // empty
      } else {
        result += escapeHtml(val);
      }
    }
  }
  return new RawHtml(result);
}

export function $(selector, parent = document) {
  return parent.querySelector(selector);
}

export function $$(selector, parent = document) {
  return Array.from(parent.querySelectorAll(selector));
}

export function setHtml(el, content) {
  if (typeof el === 'string') el = $(el);
  if (!el) return;
  if (content instanceof RawHtml) {
    el.innerHTML = content.content;
  } else if (typeof content === 'string') {
    el.innerHTML = content;
  }
}

export function createElement(htmlStr) {
  const str = htmlStr instanceof RawHtml ? htmlStr.content : String(htmlStr || '');
  const template = document.createElement('template');
  template.innerHTML = str.trim();
  return template.content.firstElementChild;
}
