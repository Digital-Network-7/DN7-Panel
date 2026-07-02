// =========================================================================
// Auth state store
// =========================================================================
// Owns the session token (persisted to localStorage) and the current-user
// record (`me`: identity, role, 2FA, profile). Page scripts read/update auth
// through this store instead of poking a shared global, so the persistence and
// "who am I / what may I do" semantics live in one place.
const Auth = {
  // Bearer session token; seeded from localStorage so a reload stays signed in.
  token: localStorage.getItem('dn7_web_token') || '',
  // Current user record from /api/me (null until loaded).
  me: null,

  /// Persist a freshly-minted session token (after a successful login).
  setToken(t) {
    this.token = t || '';
    if (this.token) localStorage.setItem('dn7_web_token', this.token);
    else localStorage.removeItem('dn7_web_token');
  },

  /// Forget the session (logout): clears the token + cached user.
  clear() {
    this.token = '';
    this.me = null;
    localStorage.removeItem('dn7_web_token');
  },

  // ---- Permission helpers (consume `me` so callers don't re-derive roles) ----
  isSuper() { return !!(this.me && this.me.is_super); },
  isAdmin() { return !!(this.me && this.me.is_admin); },
  // Privilege level: owner(super)=2, admin=1, user=0.
  level() { const m = this.me || {}; return m.is_super ? 2 : (m.is_admin ? 1 : 0); },
};

// Cross-tab session coherence: 'storage' fires here when ANOTHER tab writes the
// token key. Sign-out there → drop the revoked session and show login; a
// different session signed in there → reload to resync (prepaint re-reads it).
window.addEventListener('storage', (e) => {
  if (e.key !== 'dn7_web_token') return;
  const nv = e.newValue || '';
  if (nv === Auth.token) return;
  if (!nv) {
    const wasIn = document.documentElement.getAttribute('data-auth') === 'in';
    Auth.clear();
    if (wasIn) {
      stopTab();
      document.documentElement.setAttribute('data-auth', 'out');
      $('app').classList.add('hidden');
      $('login').classList.remove('hidden');
      toast(tr('auth.ended_elsewhere'), 'info');
    }
  } else {
    location.reload();
  }
});
