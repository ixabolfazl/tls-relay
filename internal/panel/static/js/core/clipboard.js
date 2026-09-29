/**
 * Safe clipboard helper with insecure-context fallback.
 *
 * @param {string} text - The text to copy to the clipboard.
 * @returns {Promise<boolean>} True if the copy succeeded, false otherwise.
 */
export async function copyText(text) {
  if (text === null || text === undefined) {
    text = '';
  } else if (typeof text !== 'string') {
    text = String(text);
  }

  // Modern async clipboard API in secure contexts
  if (
    typeof window !== 'undefined' &&
    window.isSecureContext &&
    typeof navigator !== 'undefined' &&
    navigator.clipboard &&
    typeof navigator.clipboard.writeText === 'function'
  ) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through to textarea execCommand fallback
    }
  }

  // Fallback: off-screen textarea with document.execCommand('copy')
  if (typeof document === 'undefined' || !document.body) {
    return false;
  }

  let textarea = null;
  try {
    textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.top = '-9999px';
    textarea.style.left = '-9999px';
    textarea.style.opacity = '0';
    textarea.style.pointerEvents = 'none';
    textarea.setAttribute('readonly', '');
    textarea.setAttribute('aria-hidden', 'true');
    document.body.appendChild(textarea);

    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, text.length);

    const success = document.execCommand('copy');
    return Boolean(success);
  } catch {
    return false;
  } finally {
    if (textarea && textarea.parentNode) {
      textarea.parentNode.removeChild(textarea);
    }
  }
}
