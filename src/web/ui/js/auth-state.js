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
