(function(){
  const controllers = new Map();
  const controllersByTarget = new Map();
  let openSelect = null;

  function close(root){
    if(!root) return;
    root.setAttribute('data-open', 'false');
    const trigger = root.querySelector('[data-select-trigger]');
    if(trigger) trigger.setAttribute('aria-expanded', 'false');
    if(openSelect === root) openSelect = null;
  }

  function closeAll(except){
    controllers.forEach((controller, element)=>{
      if(element !== except){
        close(element);
      }
    });
    if(!except){
      openSelect = null;
    }
  }

  function init(root){
    if(!root || controllers.has(root)) return;
    const targetId = root.getAttribute('data-target');
    const hidden = targetId ? document.getElementById(targetId) : null;
    const trigger = root.querySelector('[data-select-trigger]');
    const label = root.querySelector('[data-select-label]');
    const options = Array.from(root.querySelectorAll('[data-select-option]'));
    const placeholder = root.getAttribute('data-placeholder') || (label ? label.textContent.trim() : '선택하세요');

    root.setAttribute('data-open', 'false');

    if(trigger){
      trigger.setAttribute('type', 'button');
      trigger.setAttribute('aria-haspopup', 'listbox');
      trigger.setAttribute('aria-expanded', 'false');
    }
    const optionIds = new Set();
    options.forEach((btn, index)=>{
      btn.setAttribute('type', 'button');
      btn.setAttribute('role', 'option');
      if(!btn.id){
        btn.id = `${targetId || 'looma-select'}-option-${index}`;
      }
      optionIds.add(btn.id);
    });
    if(trigger && trigger.id){
      trigger.setAttribute('aria-controls', Array.from(optionIds).join(' '));
    }

    function setVisualValue(value, text, { emit = true } = {}){
      const normalized = typeof value === 'string' ? value : '';
      if(hidden) hidden.value = normalized;
      if(label) label.textContent = normalized ? (text || placeholder) : placeholder;
      options.forEach((btn)=>{
        const active = btn.dataset.value === normalized;
        btn.classList.toggle('active', active);
        btn.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      root.dataset.value = normalized;
      if(emit){
        root.dispatchEvent(new CustomEvent('looma-select-change', { detail: { value: normalized } }));
      }
    }

    const controller = {
      root,
      targetId,
      set(value){
        const normalized = typeof value === 'string' ? value : '';
        const match = options.find((btn)=> btn.dataset.value === normalized);
        setVisualValue(normalized, match ? match.textContent.trim() : '', { emit: false });
      },
      get(){
        return root.dataset.value || '';
      },
    };

    controllers.set(root, controller);
    if(targetId) controllersByTarget.set(targetId, controller);

    const toggle = ()=>{
      const isOpen = root.getAttribute('data-open') === 'true';
      if(isOpen){
        close(root);
      }else{
        closeAll(root);
        root.setAttribute('data-open', 'true');
        if(trigger) trigger.setAttribute('aria-expanded', 'true');
        openSelect = root;
      }
    };

    trigger?.addEventListener('click', (event)=>{
      event.preventDefault();
      toggle();
    });

    options.forEach((btn)=>{
      btn.addEventListener('click', (event)=>{
        event.preventDefault();
        const value = btn.dataset.value || '';
        const text = btn.textContent.trim();
        setVisualValue(value, text);
        close(root);
      });
    });

    const initialValue = hidden?.value || '';
    const initialOption = options.find((btn)=> btn.dataset.value === initialValue);
    setVisualValue(initialValue, initialOption ? initialOption.textContent.trim() : '', { emit: false });
  }

  function scan(scope){
    const context = scope || document;
    context.querySelectorAll('[data-looma-select]').forEach(init);
  }

  document.addEventListener('click', (event)=>{
    const within = event.target.closest('[data-looma-select]');
    if(!within){
      closeAll(null);
    }
  });

  document.addEventListener('keydown', (event)=>{
    if(event.key === 'Escape'){
      closeAll(null);
    }
  });

  document.addEventListener('focusin', (event)=>{
    if(openSelect && !openSelect.contains(event.target)){
      close(openSelect);
    }
  });

  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', ()=> scan());
  }else{
    scan();
  }

  window.LoomaSelect = {
    scan,
    set(targetId, value){
      const controller = controllersByTarget.get(targetId);
      if(controller){
        controller.set(value);
      }
    },
    get(targetId){
      const controller = controllersByTarget.get(targetId);
      return controller ? controller.get() : '';
    },
    closeAll: () => closeAll(null),
  };
})();
