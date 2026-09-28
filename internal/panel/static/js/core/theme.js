/**
 * Theme manager for light and dark modes with persistence and no flash.
 */

export function getTheme() {
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light';
}

export function setTheme(theme) {
  const isDark = theme === 'dark';
  document.documentElement.classList.toggle('dark', isDark);
  try {
    localStorage.setItem('relay_theme', theme);
  } catch {
    // Ignore localStorage restrictions
  }
  window.dispatchEvent(new CustomEvent('theme:change', { detail: { theme } }));
}

export function toggleTheme() {
  const next = getTheme() === 'dark' ? 'light' : 'dark';
  setTheme(next);
  return next;
}
