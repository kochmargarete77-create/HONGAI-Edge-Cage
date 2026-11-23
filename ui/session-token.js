(function installDashboardSession(root) {
  const storageKey = 'hongai.edge-cage.dashboard-token';

  function resolveToken(context = root) {
    const location = context.location;
    const history = context.history;
    const storage = context.sessionStorage;
    const fragment = new URLSearchParams((location.hash || '').replace(/^#/, ''));
    const fragmentToken = fragment.get('token') || '';

    if (fragmentToken) {
      try { storage.setItem(storageKey, fragmentToken); } catch {}
    }

    let storedToken = '';
    try { storedToken = storage.getItem(storageKey) || ''; } catch {}
    const token = fragmentToken || storedToken;

    if (location.hash) {
      history.replaceState(null, '', `${location.pathname}${location.search || ''}`);
    }
    return token;
  }

  root.HongAiDashboardSession = Object.freeze({ resolveToken, storageKey });
})(globalThis);
