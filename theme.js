(function(){
  const STORAGE_KEY = 'looma:theme';
  const root = document.documentElement;
  const listeners = new Set();
  const metaTheme = document.querySelector('meta[name="theme-color"]');
  const prefersDark = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  let current = 'auto';

  function resolve(theme){
    if(theme === 'auto'){
      if(prefersDark && typeof prefersDark.matches === 'boolean'){
        return prefersDark.matches ? 'dark' : 'light';
      }
      return 'dark';
    }
    return theme;
  }

  function updateAttributes(theme){
    if(theme === 'auto'){
      root.removeAttribute('data-theme');
    }else{
      root.setAttribute('data-theme', theme);
    }
    root.dataset.themePreference = theme;
    root.dataset.themeResolved = resolve(theme);
  }

  function updateMeta(theme){
    if(!metaTheme) return;
    const resolved = resolve(theme);
    const color = resolved === 'light' ? '#F7F8FA' : '#0A0A0A';
    metaTheme.setAttribute('content', color);
  }

  function apply(theme, { persist = true, silent = false } = {}){
    const normalized = theme === 'light' || theme === 'dark' || theme === 'auto' ? theme : 'auto';
    if(persist){
      try{
        localStorage.setItem(STORAGE_KEY, normalized);
      }catch(err){
        /* ignore storage errors */
      }
    }
    current = normalized;
    updateAttributes(normalized);
    updateMeta(normalized);
    if(!silent){
      listeners.forEach((fn)=>{
        try{ fn(normalized); }catch(err){ /* ignore */ }
      });
    }
  }

  function init(){
    let stored = 'auto';
    try{
      const value = localStorage.getItem(STORAGE_KEY);
      if(value === 'light' || value === 'dark' || value === 'auto'){
        stored = value;
      }
    }catch(err){
      /* ignore */
    }
    apply(stored, { persist: false, silent: true });
  }

  if(prefersDark){
    const handler = () => {
      if(current === 'auto'){
        apply('auto', { persist: false });
      }
    };
    if(typeof prefersDark.addEventListener === 'function'){
      prefersDark.addEventListener('change', handler);
    }else if(typeof prefersDark.addListener === 'function'){
      prefersDark.addListener(handler);
    }
  }

  window.addEventListener('storage', (event)=>{
    if(event.key === STORAGE_KEY && event.newValue){
      if(event.newValue === current) return;
      apply(event.newValue, { persist: false });
    }
  });

  init();

  window.LoomaTheme = {
    get: () => current,
    set: (theme) => apply(theme),
    onChange: (fn) => {
      if(typeof fn !== 'function') return () => {};
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    resolve: () => resolve(current),
  };
})();
