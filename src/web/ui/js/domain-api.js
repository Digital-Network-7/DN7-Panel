// =========================================================================
// Domain API clients
// =========================================================================
// Page-agnostic wrappers over the raw api()/op() network layer, grouped by
// domain. Page scripts call e.g. AccountApi.changePassword(body) instead of
// hand-assembling paths and JSON, so endpoint shapes live in one place and the
// pages don't depend on URL/field conventions directly. Each method returns the
// same promise api() does (the parsed { ok, data, ... } body), so callers keep
// their existing `.then(b => ...)` handling.
//
// First domains migrated: account (self-service + user management) and
// settings/branding. Docker/Website/MySQL can follow the same shape.

const AccountApi = {
  // Self-service.
  me() { return api('/api/me'); },
  updateProfile(body) { return api('/api/profile', { method: 'POST', body: JSON.stringify(body) }); },
  changePassword(body) { return api('/api/password', { method: 'POST', body: JSON.stringify(body) }); },
  twofaSetup() { return api('/api/2fa/setup', { method: 'POST' }); },
  twofaEnable(code) { return api('/api/2fa/enable', { method: 'POST', body: JSON.stringify({ code }) }); },
  twofaDisable(code) { return api('/api/2fa/disable', { method: 'POST', body: JSON.stringify({ code }) }); },
  // User management (admin).
  listUsers() { return api('/api/users'); },
  createUser(body) { return api('/api/users', { method: 'POST', body: JSON.stringify(body) }); },
  updateUser(body) { return api('/api/users/update', { method: 'POST', body: JSON.stringify(body) }); },
  deleteUser(username) { return api('/api/users/delete', { method: 'POST', body: JSON.stringify({ username }) }); },
};

const SettingsApi = {
  get() { return api('/api/settings'); },
  save(body, headers) { return api('/api/settings', { method: 'POST', body: JSON.stringify(body), headers: headers || {} }); },
  saveBranding(body) { return api('/api/branding', { method: 'POST', body: JSON.stringify(body) }); },
};
