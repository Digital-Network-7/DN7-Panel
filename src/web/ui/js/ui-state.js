// =========================================================================
// UI state store
// =========================================================================
// Owns view-level UI state — currently the active top-level tab, persisted to
// localStorage so a reload reopens the same section. Page scripts set the tab
// through `UI.setTab` rather than writing a shared global directly.
const UI = {
  // Active top-level tab key (e.g. 'dash' | 'docker' | 'website' | ...).
  tab: localStorage.getItem('dn7_tab') || 'dash',

  /// Switch the active tab and persist it (best-effort; storage may be denied).
  setTab(k) {
    this.tab = k;
    try { localStorage.setItem('dn7_tab', k); } catch (e) {}
  },
};
