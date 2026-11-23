(function installDashboardSession(root) {
  const storageKey = 'hongai.edge-cage.dashboard-token';

  function clearToken(context = root) {
    try { context.sessionStorage.removeItem(storageKey); } catch {}
  }

  async function resolveToken(context = root) {
    const location = context.location;
    const history = context.history;
    const storage = context.sessionStorage;
    const fragment = new URLSearchParams((location.hash || '').replace(/^#/, ''));
    const bootstrapToken = fragment.get('token') || '';

    let storedToken = '';
    try { storedToken = storage.getItem(storageKey) || ''; } catch {}
    if (!bootstrapToken) {
      if (location.hash) history.replaceState(null, '', `${location.pathname}${location.search || ''}`);
      return storedToken;
    }

    try {
      const response = await context.fetch('/api/session', {
        method: 'POST',
        headers: { Authorization: `Bearer ${bootstrapToken}` },
        cache: 'no-store',
        redirect: 'error'
      });
      const payload = await response.json();
      if (!response.ok || typeof payload.sessionToken !== 'string') {
        throw new Error(payload.error || 'Dashboard session exchange failed.');
      }
      try { storage.setItem(storageKey, payload.sessionToken); } catch {}
      history.replaceState(null, '', `${location.pathname}${location.search || ''}`);
      return payload.sessionToken;
    } catch (error) {
      clearToken(context);
      throw error;
    }
  }

  root.HongAiDashboardSession = Object.freeze({ resolveToken, clearToken, storageKey });
})(globalThis);
