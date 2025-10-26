(() => {
  const BADGE_SELECTOR = '[data-notif-count]';
  const nodes = () => document.querySelectorAll(BADGE_SELECTOR);
  if (!nodes().length) return;

  let fetching = false;

  async function refresh() {
    if (fetching) return;
    fetching = true;
    try {
      const res = await fetch('/api/notifications/count', {
        method: 'GET',
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      });
      if (!res.ok) throw new Error('count-failed');
      const data = await res.json();
      const count = Number(data?.count) || 0;
      updateBadge(count);
    } catch (err) {
      updateBadge(0);
    } finally {
      fetching = false;
    }
  }

  function updateBadge(count) {
    const display = count > 99 ? '99+' : String(count);
    nodes().forEach((el) => {
      if (count > 0) {
        el.textContent = display;
        el.classList.remove('hidden');
      } else {
        el.textContent = '';
        el.classList.add('hidden');
      }
    });
  }

  refresh();
  setInterval(refresh, 60000);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) refresh();
  });
  window.addEventListener('looma:notifications-read', () => {
    refresh();
  });
})();
