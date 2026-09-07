// broker/lib/admin-visibility.js — shared contract for dashboard admin chrome.
// Dashboard classic scripts inline the same rules; this module is the testable source.

/**
 * @param {unknown} ident
 * @returns {boolean}
 */
export function isAdminIdentity(ident) {
  return !!(ident && typeof ident === 'object' && ident.role === 'admin');
}

/**
 * @param {boolean} isAdmin
 * @param {Iterable<{ hidden: boolean }>} elements
 */
export function applyAdminVisibility(isAdmin, elements) {
  const hide = !isAdmin;
  for (const el of elements) {
    el.hidden = hide;
  }
}
