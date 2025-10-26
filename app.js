/* Looma/app.js — 서버 연동 버전 (목업 제거)
   - 실제 API 호출로 게시/댓글 처리
   - 게스트 1회 댓글 + 4자리 비번(서버 검증/저장)
   - 로그인 안한 사용자는 게시 업로드 차단(모달)
   - 관리자 allowAnon 토글은 서버가 보유
*/
(() => {
  // ===== DOM helpers
  const $ = (s, r=document)=>r.querySelector(s);
  const $$ = (s, r=document)=>Array.from(r.querySelectorAll(s));
  const on = (el, ev, fn, opts)=> el && el.addEventListener(ev, fn, opts);

  // ===== Client state
  const state = {
    session: null,          // {user:{id,handle,name}} | null
    config: { allowAnon:true, basicPostingRestricted:false },
    attachments: [],        // [{type:'image'|'video', url, meta:{ratio,zoom,tx,ty,duration}}] - (서버 업로드는 아직 보류)
    posts: [],              // 서버에서 로드
    summary: {
      trending: [],
      suggestedUsers: [],
    },
    pinnedNotice: null,
  };

  // ===== Fetch helpers
  async function api(path, opts={}) {
    const res = await fetch(path, {
      method: opts.method || 'GET',
      headers: { 'Content-Type':'application/json', ...(opts.headers||{}) },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      credentials: 'include', // 세션 쿠키 포함
    });
    if (!res.ok) {
      const msg = await res.text().catch(()=>res.statusText);
      throw new Error(msg || `HTTP ${res.status}`);
    }
    const ct = res.headers.get('content-type') || '';
    return ct.includes('application/json') ? res.json() : res.text();
  }
  function toast(msg) {
    const root = $('#toastRoot'); if (!root) return alert(msg);
    const el = document.createElement('div');
    el.style.cssText = 'margin-top:8px;padding:10px 12px;border-radius:10px;border:1px solid #2a2a2a;background:#111;color:#fff;opacity:0;transform:translateY(6px);transition:.2s';
    el.textContent = msg;
    root.appendChild(el);
    requestAnimationFrame(()=>{ el.style.opacity='1'; el.style.transform='none'; });
    setTimeout(()=>{ el.style.opacity='0'; el.style.transform='translateY(6px)'; setTimeout(()=> el.remove(), 200); }, 1800);
  }
  function openModal(sel){
    const m = $(sel);
    if(!m) return;
    m.classList.add('open');
    m.setAttribute('aria-hidden','false');
    switch(sel){
      case '#modal-report':
        if(window.LoomaSelect && typeof window.LoomaSelect.set === 'function'){
          const current = reportReason?.value || '';
          window.LoomaSelect.set('reportReason', current);
        }
        break;
      default:
        break;
    }
  }
  function closeModal(el){ const m=typeof el==='string' ? $(el) : el.closest('.modal'); if(!m) return; m.classList.remove('open'); m.setAttribute('aria-hidden','true'); }
  $$('[data-close]').forEach(b=> on(b,'click',()=> closeModal(b.getAttribute('data-close'))));

  // ===== Modal refs
  const modalCommentEdit = $('#modal-comment-edit');
  const modalCommentDelete = $('#modal-comment-delete');
  const commentEditForm = $('#commentEditForm');
  const commentEditText = $('#commentEditText');
  const commentEditPwRow = $('#commentEditPwRow');
  const commentEditPw = $('#commentEditPw');
  const commentDeleteForm = $('#commentDeleteForm');
  const commentDeletePwRow = $('#commentDeletePwRow');
  const commentDeletePw = $('#commentDeletePw');
  const modalPostActions = $('#modal-post-actions');
  const postActionsList = $('#postActionsList');
  const postEditForm = $('#postEditForm');
  const postEditText = $('#postEditText');
  const postDeleteForm = $('#postDeleteForm');
  const modalReport = $('#modal-report');
  const reportForm = $('#reportForm');
  const reportReason = $('#reportReason');
  const reportDetail = $('#reportDetail');
  if(window.LoomaSelect && typeof window.LoomaSelect.scan === 'function'){
    window.LoomaSelect.scan();
  }
  const btnMedia = $('#btnMedia');
  const btnPoll = $('#btnPoll');
  const btnEmoji = $('#btnEmoji');
  const emojiPicker = $('#emojiPicker');
  const pinnedNoticeCard = $('#pinnedNotice');
  const pinnedNoticeTitle = pinnedNoticeCard?.querySelector('[data-title]');
  const pinnedNoticeBody = pinnedNoticeCard?.querySelector('[data-body]');
  const pollForm = $('#pollForm');
  const pollQuestion = $('#pollQuestion');
  const pollOptionInputs = $$('.poll-option');
  const mediaViewer = $('#modal-media-viewer');
  const viewerImage = $('#viewerImage');
  const viewerVideo = $('#viewerVideo');
  const btnAuthAction = $('#btnAuthAction');
  const btnLogout = $('#btnLogout');
  const sidebarSigned = $('#sidebarSigned');
  const sidebarGuest = $('#sidebarGuest');
  const sidebarName = $('#sidebarName');
  const sidebarHandle = $('#sidebarHandle');
  const suggestionsBody = $('#suggestionsBody');
  const trendsBody = $('#trendsBody');
  let editTarget = null;
  let deleteTarget = null;
  let postActionsTarget = null;
  let postEditTarget = null;
  let postDeleteTarget = null;
  let reportTarget = null;

  function toggleHidden(el, hide){ if(!el) return; el.classList[hide ? 'add' : 'remove']('hidden'); }
  function isAdminClient(){
    const user = state.session?.user;
    if(!user) return false;
    const role = String(user.role || '').toLowerCase();
    if(role === 'admin' || role === 'superadmin') return true;
    return user.isSuperAdmin === true;
  }
  function isWriteLocked(){
    return !!state.config.basicPostingRestricted && !isAdminClient();
  }
  function isOwnerPost(postId){
    if(!postId || !state.session?.user) return false;
    const post = state.posts.find((p)=> p.id===postId);
    return !!(post && post.author && post.author.id === state.session.user.id);
  }

  // ===== ViewTransition for [data-nav]
  (function setupNav(){
    const path = location.pathname.split('/').pop() || 'home.html';
    $$('a[data-nav]').forEach(a=>{
      const href=a.getAttribute('href')||'';
      if(href===path) a.classList.add('active');
      on(a,'click',e=>{
        if(!href || href.startsWith('#') || href.startsWith('http')) return;
        e.preventDefault();
        if(href===path) return;
        if(document.startViewTransition){
          document.startViewTransition(()=> location.href=href);
        }else{
          document.body.style.opacity='0'; setTimeout(()=> location.href=href, 140);
        }
      });
    });
  })();

  // ===== Attachments tray (클라 미리보기용)
  const tray = $('#attachments');
  function formatDuration(sec){ sec=Math.max(0,Math.round(sec||0)); const m=Math.floor(sec/60), s=sec%60; return `${m}:${String(s).padStart(2,'0')}`; }
  function renderAttachments(){
    if(!tray) return; tray.innerHTML='';
    state.attachments.forEach((a,idx)=>{
      const tile=document.createElement('div'); tile.dataset.idx=String(idx);
      if(a.type==='poll'){
        tile.className='thumb poll';
        const title=document.createElement('div'); title.className='poll-q'; title.textContent=a.data?.question || '투표';
        const list=document.createElement('ul');
        (a.data?.options || []).forEach(opt=>{
          const li=document.createElement('li'); li.textContent=opt; list.appendChild(li);
        });
        if(!list.children.length){ const li=document.createElement('li'); li.textContent='옵션 없음'; list.appendChild(li); }
        tile.appendChild(title); tile.appendChild(list);
      }else if(a.type==='image'){
        tile.className='thumb';
        const im=document.createElement('img'); im.src=a.url; im.alt='첨부 이미지'; tile.appendChild(im);
        const bd=document.createElement('div'); bd.className='badge'; bd.textContent=a.meta?.ratio||'1:1'; tile.appendChild(bd);
      }else if(a.type==='video'){
        tile.className='thumb';
        const vd=document.createElement('video'); vd.src=a.url; vd.muted=true; vd.playsInline=true; vd.preload='metadata'; tile.appendChild(vd);
        const ic=document.createElement('div'); ic.className='vi'; ic.innerHTML='<i class="ri-play-fill"></i>'; tile.appendChild(ic);
        const bd=document.createElement('div'); bd.className='badge'; bd.textContent=formatDuration(a.meta?.duration); tile.appendChild(bd);
      }else{
        tile.className='thumb';
        const label=document.createElement('div'); label.style.cssText='display:flex;align-items:center;justify-content:center;height:100%;font-size:12px;padding:6px;text-align:center;background:#111;';
        label.textContent=a.filename || '첨부';
        tile.appendChild(label);
      }
      const x=document.createElement('button'); x.className='close'; x.setAttribute('aria-label','첨부 삭제'); x.textContent='×';
      on(x,'click',(ev)=>{ ev.stopPropagation(); try{ if(state.attachments[idx]?.url) URL.revokeObjectURL(state.attachments[idx].url); }catch{} state.attachments.splice(idx,1); renderAttachments(); });
      tile.appendChild(x);
      tray.appendChild(tile);
    });
  }
  function clearAttachments(){ state.attachments.forEach(a=>{ try{URL.revokeObjectURL(a.url);}catch{} }); state.attachments=[]; currentImageFile = null; renderAttachments(); }

  // ===== IG-style media editor
  const picker = $('#mediaPicker');
  const editor = $('#editor');
  const imgEl = $('#editImg');
  const stage = $('#stage');
  const btnClose = $('#editorClose');
  const btnDone = $('#editorDone');
  const chips = $$('.editor-bottom .chip');
  const MAX_VIDEO_SECONDS = 60;
  let ratio='1/1', zoom=1, tx=0, ty=0, baseZoom=1, pinchStartDist=0, lastTap=0;
  let currentImageFile = null;
  function openEditor(){ editor?.classList.add('open'); editor?.setAttribute('aria-hidden','false'); }
  function closeEditor(){ editor?.classList.remove('open'); editor?.setAttribute('aria-hidden','true'); if(imgEl) imgEl.src=''; resetTransform(); currentImageFile = null; }
  function setRatio(r){ ratio=r; if(stage) stage.style.aspectRatio=r; chips.forEach(c=> c.classList.toggle('active', c.dataset.r===r)); }
  function resetTransform(){ zoom=1; tx=0; ty=0; applyTransform(); }
  function applyTransform(){ if(imgEl) imgEl.style.transform=`translate(-50%,-50%) translate(${tx}px, ${ty}px) scale(${zoom})`; }
  function dist(a,b){ const dx=a.clientX-b.clientX, dy=a.clientY-b.clientY; return Math.hypot(dx,dy); }
  chips.forEach(c=> on(c,'click',()=> setRatio(c.dataset.r)));
  on(btnMedia,'click',()=> {
    if(!state.session?.user){ openModal('#modal-login-post'); return; }
    picker?.click();
  });
  on(btnClose,'click',closeEditor);
  on(btnDone,'click',()=>{
    if(!imgEl?.src || !currentImageFile){ closeEditor(); return; }
    state.attachments.push({type:'image', url:imgEl.src, meta:{ratio,zoom,tx,ty}, file: currentImageFile});
    renderAttachments();
    currentImageFile = null;
    closeEditor();
  });
  on(picker,'change',(e)=>{
    const f=e.target.files?.[0]; if(!f) return;
    if(f.type.startsWith('image/')){ const url=URL.createObjectURL(f); currentImageFile = f; if(imgEl) imgEl.src=url; setRatio('1/1'); resetTransform(); openEditor(); }
    else if(f.type.startsWith('video/')){
      const v=document.createElement('video'); v.preload='metadata';
      v.onloadedmetadata=()=>{ URL.revokeObjectURL(v.src); const d=v.duration||0;
        if(d>MAX_VIDEO_SECONDS){ toast(`영상 ${Math.round(d)}초 → 제한 60초 초과`); picker.value=''; }
        else { const url=URL.createObjectURL(f); state.attachments.push({type:'video', url, meta:{duration:d}, file:f}); renderAttachments(); }
      }; v.src=URL.createObjectURL(f);
    } else { toast('이미지/영상 파일을 선택해 주세요.'); }
    e.target.value='';
  });

  on(btnPoll,'click',()=>{
    if(!state.session?.user){ openModal('#modal-login-post'); return; }
    if(!pollForm) return;
    pollForm.reset();
    pollForm.querySelectorAll('.poll-option').forEach((input, idx)=>{
      input.required = idx < 2;
    });
    openModal('#modal-poll');
  });

  on(pollForm,'submit',(e)=>{
    e.preventDefault();
    if(!pollQuestion) return;
    const question = (pollQuestion.value || '').trim();
    const options = pollOptionInputs.map((input)=> (input.value || '').trim()).filter(Boolean);
    if(question.length < 2){ toast('투표 질문을 입력하세요'); return; }
    if(options.length < 2){ toast('옵션을 두 개 이상 입력하세요'); return; }
    state.attachments.push({ type:'poll', data:{ question, options }, meta:{ question, options } });
    renderAttachments();
    pollForm.reset();
    closeModal('#modal-poll');
  });

  let emojiPickerOpen = false;
  function hideEmojiPicker(){
    if(!emojiPicker) return;
    emojiPicker.classList.add('hidden');
    emojiPicker.setAttribute('aria-hidden','true');
    emojiPickerOpen = false;
  }
  function showEmojiPicker(){
    if(!emojiPicker || !btnEmoji) return;
    const rect = btnEmoji.getBoundingClientRect();
    emojiPicker.style.top = `${rect.bottom + window.scrollY + 8}px`;
    emojiPicker.style.left = `${rect.left + window.scrollX}px`;
    emojiPicker.classList.remove('hidden');
    emojiPicker.setAttribute('aria-hidden','false');
    emojiPickerOpen = true;
  }

  on(btnEmoji,'click',(e)=>{
    e.preventDefault();
    if(!state.session?.user){ openModal('#modal-login-post'); return; }
    if(!composerText || composerText.disabled){ toast('로그인 후 이용할 수 있습니다'); return; }
    if(emojiPickerOpen){ hideEmojiPicker(); }
    else{ showEmojiPicker(); }
  });

  if(emojiPicker){
    emojiPicker.addEventListener('click',(e)=>{
      const btn = e.target.closest('button[data-emoji]');
      if(!btn) return;
      e.preventDefault();
      const emoji = btn.getAttribute('data-emoji') || '';
      if(composerText && !composerText.disabled){
        insertAtCursor(composerText, emoji);
      }
      hideEmojiPicker();
    });
  }

  document.addEventListener('click',(e)=>{
    if(!emojiPickerOpen) return;
    if(emojiPicker && (emojiPicker.contains(e.target) || btnEmoji?.contains(e.target))) return;
    hideEmojiPicker();
  });
  window.addEventListener('scroll', ()=>{ if(emojiPickerOpen) hideEmojiPicker(); }, { passive:true });

  function resetMediaViewer(){
    if(viewerVideo){
      viewerVideo.pause();
      viewerVideo.removeAttribute('src');
      viewerVideo.load();
      viewerVideo.style.display='none';
    }
    if(viewerImage){
      viewerImage.src='';
      viewerImage.style.display='none';
    }
  }
  function openMediaViewer(type, src){
    if(!src) return;
    resetMediaViewer();
    if(type==='image' && viewerImage){
      viewerImage.src = src;
      viewerImage.style.display='block';
    }else if(type==='video' && viewerVideo){
      viewerVideo.src = src;
      viewerVideo.style.display='block';
      viewerVideo.load();
      viewerVideo.play().catch(()=>{});
    }
    openModal('#modal-media-viewer');
  }
  // drag/pinch/zoom
  let dragging=false, sx=0, sy=0;
  on(stage,'mousedown',(ev)=>{ if(!imgEl?.src) return; dragging=true; sx=ev.clientX; sy=ev.clientY; ev.preventDefault(); });
  on(window,'mousemove',(ev)=>{ if(!dragging||!imgEl?.src) return; tx+=(ev.clientX-sx); ty+=(ev.clientY-sy); sx=ev.clientX; sy=ev.clientY; applyTransform(); });
  on(window,'mouseup',()=> dragging=false);
  on(stage,'touchstart',(ev)=>{ if(!imgEl?.src) return; if(ev.touches.length===2){ pinchStartDist=dist(ev.touches[0],ev.touches[1]); baseZoom=zoom; } }, {passive:true});
  on(stage,'touchmove',(ev)=>{ if(!imgEl?.src) return;
    if(ev.touches.length===2){ const d=dist(ev.touches[0],ev.touches[1]); const r=d/(pinchStartDist||d); zoom=Math.min(3,Math.max(1,baseZoom*r)); applyTransform(); }
    else if(ev.touches.length===1){ const t=ev.touches[0]; if(stage._px!=null){ tx+=(t.clientX-stage._px); ty+=(t.clientY-stage._py); applyTransform(); } stage._px=t.clientX; stage._py=t.clientY; }
  }, {passive:true});
  on(stage,'touchend',()=>{ stage._px=stage._py=null; });
  on(stage,'wheel',(ev)=>{ if(!imgEl?.src) return; ev.preventDefault(); const step=-ev.deltaY/600; zoom=Math.min(3,Math.max(1,zoom*(1+step))); applyTransform(); }, {passive:false});
  on(stage,'click',()=>{ const now=Date.now(); if(now-lastTap<250){ zoom=(zoom<1.8)?2:1; applyTransform(); } lastTap=now; });

  // ===== Session / Config / Posts load
  async function loadInitial(){
    try {
      state.config = await api('/api/config');
      state.config.basicPostingRestricted = !!state.config.basicPostingRestricted;
    } catch { /* default true */ }
    try {
      state.session = await api('/api/session');
    } catch { state.session = { user:null }; }
    updateAuthUI();
    await Promise.all([loadPosts(), loadSummary(), loadPinnedNotice()]);
  }
  async function mergeOwnPostsIfNeeded(){
    if(!state.session?.user) return;
    if((state.posts || []).length >= 5) return;
    try{
      const params = new URLSearchParams();
      params.set('id', state.session.user.id);
      params.set('limit', '50');
      const profileRes = await api(`/api/users/profile?${params.toString()}`);
      const extraPosts = (profileRes?.posts || []).filter(
        (post)=> (post?.status || 'active') !== 'removed',
      );
      if(!extraPosts.length) return;
      const merged = new Map();
      (state.posts || []).forEach((post)=> merged.set(post.id, post));
      extraPosts.forEach((post)=>{ if(post?.id && !merged.has(post.id)) merged.set(post.id, post); });
      state.posts = Array.from(merged.values()).sort(
        (a,b)=> new Date(b?.createdAt || 0) - new Date(a?.createdAt || 0),
      );
    }catch(err){
      console.warn('자신의 게시물 보강에 실패했습니다.', err);
    }
  }

  async function loadPosts(){
    try{
      const data = await api('/api/posts');
      state.posts = data.posts || [];
      await mergeOwnPostsIfNeeded();
      renderPosts();
      updateOwnerFlags();
    }catch(err){
      console.error('피드 로드 실패', err);
      toast('피드를 불러오지 못했습니다.');
    }
  }

  // ===== UI binding (auth)
  const composerText = $('#composerText');
  const btnPost = $('#btnPost');
  const composerLock = $('#composerLock');

  function setAvatarBackground(el, user, fallback = '') {
    if (!el) return;
    const fallbackHandle = typeof fallback === 'string' && fallback.startsWith('@') ? fallback : '';
    if (user?.handle) {
      el.dataset.profileHandle = user.handle;
      el.classList.add('profile-link');
    } else if (fallbackHandle) {
      el.dataset.profileHandle = fallbackHandle;
      el.classList.add('profile-link');
    } else {
      if (el.dataset && 'profileHandle' in el.dataset) delete el.dataset.profileHandle;
      el.classList.remove('profile-link');
    }
    if (user?.avatarUrl) {
      const safe = String(user.avatarUrl).replace(/"/g, '%22').replace(/'/g, '%27');
      el.style.backgroundImage = `url("${safe}")`;
      el.style.backgroundSize = 'cover';
      el.style.backgroundPosition = 'center';
      if ('textContent' in el) el.textContent = '';
    } else {
      el.style.backgroundImage = '';
      if ('textContent' in el) {
        const label = user?.name || user?.handle || (fallbackHandle || fallback) || '';
        el.textContent = label ? label.trim().charAt(0).toUpperCase() : '';
      }
    }
  }

  function resolveAuthorForDisplay(author) {
    if (!author) return null;
    const viewer = state.session?.user || null;
    if (viewer && author.id === viewer.id) {
      return {
        ...author,
        avatarUrl: viewer.avatarUrl || author.avatarUrl || null,
        handle: viewer.handle || author.handle,
        name: viewer.name || author.name,
      };
    }
    return author;
  }

  function navigateToProfile(handle) {
    if (!handle) return;
    const normalized = handle.startsWith('@') ? handle.slice(1) : handle;
    if (!normalized) return;
    window.location.href = `profile.html?handle=${encodeURIComponent(normalized)}`;
  }

  function updateAuthUI(){
    const user = state.session?.user || null;
    const writeLocked = isWriteLocked();
    if(btnAuthAction){
      const icon = btnAuthAction.querySelector('i');
      if(user){
        btnAuthAction.setAttribute('aria-label','로그아웃');
        btnAuthAction.title = '로그아웃';
        if(icon) icon.className = 'ri-logout-circle-line';
      }else{
        btnAuthAction.setAttribute('aria-label','로그인');
        btnAuthAction.title = '로그인';
        if(icon) icon.className = 'ri-login-circle-line';
      }
    }
    if(composerText){
      if(!user){
        composerText.disabled = true;
        composerText.placeholder = '로그인 필요 · 게시물 업로드는 회원만 가능합니다';
      }else if(writeLocked){
        composerText.disabled = true;
        composerText.placeholder = '현재는 관리자만 게시물을 작성할 수 있습니다.';
      }else{
        composerText.disabled = false;
        composerText.placeholder = '지금 어떤 생각을 하고 있나요?';
      }
    }
    if(btnPost){
      btnPost.disabled = !user || writeLocked;
    }
    if(composerLock){
      if(writeLocked){
        composerLock.classList.remove('hidden');
        composerLock.textContent = '현재는 관리자만 게시물을 작성할 수 있습니다.';
      }else{
        composerLock.classList.add('hidden');
        composerLock.textContent = '';
      }
    }
    const guestState = $('#guestCommentState');
    if(guestState){
      if(state.config.basicPostingRestricted && !isAdminClient()){
        guestState.textContent = '현재는 관리자만 게시물과 댓글을 작성할 수 있습니다.';
      }else{
        guestState.textContent = state.config.allowAnon ? '비로그인 사용자는 최대 1회까지 댓글 작성 가능' : '현재 관리자에 의해 비로그인 댓글이 차단됨';
      }
    }
    toggleHidden(sidebarSigned, !user);
    toggleHidden(sidebarGuest, !!user);
    if(user){
      if(sidebarName) sidebarName.textContent = user.name || user.handle || '사용자';
      if(sidebarHandle) sidebarHandle.textContent = user.handle || '@user';
    }
    const sidebarFallback = user ? (user.handle || user.name || '@me') : 'Guest';
    setAvatarBackground($('#sidebarSigned .avatar'), user, sidebarFallback);
    setAvatarBackground($('#composer .avatar'), user, sidebarFallback);
    refreshPostAvatars();
    applyCommentLocks();
  }

  function formatNumber(value){
    return new Intl.NumberFormat('ko').format(value || 0);
  }

  function renderTrends(){
    if(!trendsBody) return;
    trendsBody.innerHTML = '';
    const list = state.summary.trending || [];
    if(!list.length){
      const empty = document.createElement('p');
      empty.className = 'muted';
      empty.style.margin = '6px 0';
      empty.textContent = '표시할 트렌드가 없습니다.';
      trendsBody.appendChild(empty);
      return;
    }
    list.slice(0, 8).forEach((item, index)=>{
      const row = document.createElement('div');
      row.className = 'trend-row';
      row.dataset.trendTag = item?.tag || '';
      row.setAttribute('role','button');
      row.setAttribute('tabindex','0');

      const rank = document.createElement('div');
      rank.className = 'rank';
      rank.textContent = String(index + 1).padStart(2,'0');

      const info = document.createElement('div');
      info.className = 'tinfo';
      const name = document.createElement('div');
      name.className = 'tname';
      name.textContent = item?.tag || '#';
      const meta = document.createElement('div');
      meta.className = 'tmeta';
      meta.textContent = `${formatNumber(item?.count || 0)}개 게시물`;
      info.appendChild(name);
      info.appendChild(meta);

      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'go';
      button.dataset.trendTag = item?.tag || '';
      button.innerHTML = '<i class="ri-arrow-right-up-line"></i>';

      row.appendChild(rank);
      row.appendChild(info);
      row.appendChild(button);
      trendsBody.appendChild(row);
    });
  }

  function createFollowButton(user){
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `btn ${user?.isFollowing ? '' : 'primary'}`.trim();
    const handle = user?.handle || '';
    if(handle) btn.dataset.followHandle = handle;
    btn.dataset.following = user?.isFollowing ? 'true' : 'false';
    if (user?.isSelf) {
      btn.disabled = true;
      btn.classList.remove('primary');
      btn.textContent = '나';
    } else {
      btn.textContent = user?.isFollowing ? '팔로잉' : '팔로우';
    }
    return btn;
  }

  function renderSuggestions(){
    if(!suggestionsBody) return;
    suggestionsBody.innerHTML = '';
    const list = state.summary.suggestedUsers || [];
    if(!list.length){
      const empty = document.createElement('p');
      empty.className = 'muted';
      empty.style.margin = '6px 0';
      empty.textContent = '추천할 사용자가 없습니다.';
      suggestionsBody.appendChild(empty);
      return;
    }
    list.slice(0, 6).forEach((user)=>{
      const row = document.createElement('div');
      row.className = 'user-row';
      if(user?.handle){
        row.dataset.profileHandle = user.handle;
        row.classList.add('profile-link');
      }

      const avatar = document.createElement('div');
      avatar.className = 'ava';
      setAvatarBackground(avatar, user, user?.handle || user?.name || '@user');

      const info = document.createElement('div');
      const name = document.createElement('div');
      name.className = 'uname';
      name.textContent = user?.name || user?.handle || '사용자';
      const handle = document.createElement('div');
      handle.className = 'uhandle';
      handle.textContent = user?.handle || '';
      info.appendChild(name);
      info.appendChild(handle);

      const actions = document.createElement('div');
      actions.className = 'uacts';
      const followBtn = createFollowButton(user);
      actions.appendChild(followBtn);

      if (user?.handle && !user?.isSelf) {
        const dmBtn = document.createElement('button');
        dmBtn.type = 'button';
        dmBtn.className = 'icon-btn small';
        dmBtn.dataset.dm = user.handle;
        dmBtn.title = '메시지';
        dmBtn.innerHTML = '<i class="ri-message-3-line"></i>';
        actions.appendChild(dmBtn);
      }

      row.appendChild(avatar);
      row.appendChild(info);
      row.appendChild(actions);
      suggestionsBody.appendChild(row);
    });
  }

  function updateFollowState(handle, isFollowing){
    if(!handle) return;
    const normalized = handle.startsWith('@') ? handle : `@${handle}`;
    state.summary.suggestedUsers = (state.summary.suggestedUsers || []).map((user)=>
      user.handle === normalized ? { ...user, isFollowing } : user,
    );
    renderSuggestions();
  }

  function goToExploreTag(tag){
    if(!tag) return;
    const query = tag.startsWith('#') ? tag : `#${tag}`;
    const url = `explore.html?q=${encodeURIComponent(query)}`;
    if(document.startViewTransition){
      document.startViewTransition(()=>{ location.href = url; });
    }else{
      location.href = url;
    }
  }

  function openDirectMessage(handle){
    if(!handle){
      return;
    }
    if(!state.session?.user){
      location.href = 'auth.html';
      return;
    }
    const clean = handle.replace(/^@/, '');
    try{
      localStorage.setItem('looma:openChannel', `dm:${clean}`);
    }catch{/* ignore */}
    if(document.startViewTransition){
      document.startViewTransition(()=>{ location.href = 'messages.html'; });
    }else{
      location.href = 'messages.html';
    }
  }

  async function handleFollowToggle(handle, currentlyFollowing){
    if(!handle) return;
    if(!state.session?.user){
      location.href = 'auth.html';
      return;
    }
    const normalized = handle.replace(/^@/, '');
    const method = currentlyFollowing ? 'DELETE' : 'POST';
    try{
      const res = await fetch(`/api/users/${encodeURIComponent(normalized)}/follow`, {
        method,
        credentials: 'include',
      });
      const text = await res.text().catch(()=> '');
      if(!res.ok){
        const error = new Error(text || `HTTP ${res.status}`);
        error.status = res.status;
        throw error;
      }
      updateFollowState(`@${normalized}`, !currentlyFollowing);
      toast(!currentlyFollowing ? '팔로우했습니다.' : '팔로우를 취소했습니다.');
    }catch(err){
      if(err?.status === 401){
        location.href = 'auth.html';
        return;
      }
      if(err?.status === 404){
        toast('대상을 찾을 수 없습니다.');
        return;
      }
      toast('요청을 처리하지 못했습니다.');
      console.error('follow toggle error', err);
    }
  }

  async function loadSummary(){
    if(!trendsBody && !suggestionsBody) return;
    if(trendsBody){
      trendsBody.innerHTML = '<p class="muted">불러오는 중…</p>';
    }
    if(suggestionsBody){
      suggestionsBody.innerHTML = '<p class="muted">불러오는 중…</p>';
    }
    try{
      const data = await api('/api/explore/summary');
      state.summary.trending = Array.isArray(data?.trending) ? data.trending : [];
      state.summary.suggestedUsers = Array.isArray(data?.suggestedUsers) ? data.suggestedUsers : [];
    }catch(err){
      console.error('summary load error', err);
      state.summary.trending = [];
      state.summary.suggestedUsers = [];
    }
    renderTrends();
    renderSuggestions();
  }

  function renderPinnedNotice(notice){
    if(!pinnedNoticeCard) return;
    if(!notice){
      pinnedNoticeCard.classList.add('hidden');
      pinnedNoticeCard.removeAttribute('href');
      return;
    }
    const title = notice.title || '';
    const body = notice.body || '';
    const cleanBody = body.replace(/\s+/g,' ').trim();
    const snippet = cleanBody.length > 90 ? cleanBody.slice(0,90).trim() + '…' : cleanBody;
    if(pinnedNoticeTitle) pinnedNoticeTitle.textContent = title;
    if(pinnedNoticeBody) pinnedNoticeBody.textContent = snippet || '자세한 내용을 확인해 보세요.';
    pinnedNoticeCard.classList.remove('hidden');
    pinnedNoticeCard.setAttribute('href', `notices.html?id=${encodeURIComponent(notice.id)}`);
  }

  async function loadPinnedNotice(){
    if(!pinnedNoticeCard) return;
    try{
      const res = await api('/api/announcements?pinnedOnly=true&limit=1');
      const notice = Array.isArray(res?.items) ? res.items[0] : null;
      state.pinnedNotice = notice || null;
      renderPinnedNotice(state.pinnedNotice);
    }catch(err){
      state.pinnedNotice = null;
      renderPinnedNotice(null);
    }
  }

  async function handleLogout(){
    try{
      await api('/api/logout',{ method:'POST' });
      toast('로그아웃되었습니다');
    }catch(err){
      toast('로그아웃 실패: '+err.message);
    }finally{
      state.session = { user:null };
      updateAuthUI();
    }
  }
  function handleAuthButton(ev){
    ev?.preventDefault?.();
    if(state.session?.user){
      handleLogout();
    }else{
      location.href = 'auth.html';
    }
  }
  on(btnAuthAction,'click',handleAuthButton);
  on(btnLogout,'click',handleLogout);

  // ===== Render posts
  function postHtml(p){
    const who = p.author?.handle || '@unknown';
    const you = state.session?.user?.id && p.author?.id===state.session.user.id;
    return `
      <article class="post" role="article" data-post-id="${p.id}" data-owner="${you ? 'true' : 'false'}">
        <div class="avatar lg" aria-hidden="true"></div>
        <div>
          <div style="display:flex; align-items:center; justify-content:space-between">
            <div><strong>${who}</strong> <span class="meta">· ${timeAgo(p.createdAt)}</span></div>
            <button class="pill" data-action="more"><i class="ri-more-2-fill"></i></button>
          </div>
          <p class="post-text" style="margin:.35rem 0 .5rem">${escapeHtml(p.text||'')}</p>
          ${attachmentsHtml(p)}
          <div class="comments" data-post-comments>
            ${(p.comments||[]).map(c=> commentHtml(c)).join('')}
            <form class="comment-form" data-post-id="${p.id}" data-requires-auth-or-guest="true">
              <input type="text" name="comment" placeholder="댓글 달기…"/>
              <button type="submit">게시</button>
            </form>
          </div>
        </div>
      </article>
    `;
  }
  function normalizePollOptions(att){
    const out = [];
    const viewerSelection = att.viewerSelection || null;
    const ids = Array.isArray(att.optionIds) ? att.optionIds : null;
    const texts = Array.isArray(att.optionTexts) ? att.optionTexts : null;
    const counts = Array.isArray(att.optionCounts) ? att.optionCounts : null;
    const percents = Array.isArray(att.optionPercents) ? att.optionPercents : null;

    const pushOption = (idx, idCandidate, textCandidate, countCandidate, percentCandidate, selectedCandidate)=>{
      const text = String(textCandidate || '').trim();
      if(!text) return;
      const idFromArray = ids && ids[idx] ? ids[idx] : null;
      const id = (idCandidate || idFromArray || `opt_${idx}`).toString();
      const count = Number(countCandidate || 0) || 0;
      const percent = Number(percentCandidate || 0) || 0;
      const isSelected = selectedCandidate != null ? !!selectedCandidate : (viewerSelection ? viewerSelection === id : false);
      out.push({ id, text, count, percent, isSelected });
    };

    if(Array.isArray(att.options)){
      att.options.forEach((opt, idx)=>{
        if(opt && typeof opt === 'object'){
          pushOption(idx, opt.id, opt.text ?? opt.label ?? opt.value, opt.count, opt.percent, opt.isSelected);
        }else{
          pushOption(idx, ids?.[idx], opt, counts?.[idx], percents?.[idx], viewerSelection ? viewerSelection === ids?.[idx] : false);
        }
      });
    }else if(att.options && typeof att.options === 'object'){
      Object.keys(att.options).forEach((key, idx)=>{
        const opt = att.options[key];
        if(opt && typeof opt === 'object'){
          pushOption(idx, opt.id || key, opt.text ?? opt.label ?? opt.value, opt.count, opt.percent, opt.isSelected);
        }else{
          pushOption(idx, key, opt, counts?.[idx], percents?.[idx], viewerSelection ? viewerSelection === key : false);
        }
      });
    }

    if(!out.length && ids && texts){
      ids.forEach((id, idx)=>{
        pushOption(idx, id, texts[idx], counts?.[idx], percents?.[idx], viewerSelection ? viewerSelection === id : false);
      });
    }

    if(!out.length && Array.isArray(att.meta?.options)){
      att.meta.options.forEach((text, idx)=> pushOption(idx, ids?.[idx], text, counts?.[idx], percents?.[idx], viewerSelection ? viewerSelection === ids?.[idx] : false));
    }

    return out;
  }

  function attachmentsHtml(post){
    const list = Array.isArray(post.attachments) ? post.attachments : [];
    if(!list.length) return '';
    const items = list.map((att)=>{
      if(!att) return '';
      if(att.type === 'poll'){
        const pollId = att.pollId || att.meta?.pollId || att.id || '';
        const options = normalizePollOptions(att);
        const totalVotes = Number(att.totalVotes || 0) || 0;
        const state = att.showResults ? 'results' : 'vote';
        const optionHtml = att.showResults
          ? options.map((opt)=>{
              const optionId = opt?.id || '';
              const label = typeof opt === 'string' ? opt : (opt?.text || '');
              const count = Number(opt?.count || 0) || 0;
              const pctRaw = typeof opt?.percent === 'number' ? opt.percent : (totalVotes ? (count / totalVotes) * 100 : 0);
              const pct = Math.max(0, Math.round(pctRaw));
              const displayPct = totalVotes ? Math.min(100, Math.max(pct, (opt?.isSelected && pct < 7) ? 7 : pct)) : 0;
              const selected = opt?.isSelected ? ' selected' : '';
              return `
                <div class="poll-result${selected}" data-option-id="${escapeHtml(optionId)}">
                  <div class="poll-result-label">${escapeHtml(label)}</div>
                  <div class="poll-result-bar">
                    <span class="fill" style="width:${displayPct}%"></span>
                    <span class="value">${totalVotes ? `${pct}%` : '0%'}</span>
                  </div>
                  <div class="poll-result-count">${totalVotes ? `${count}표` : '첫 투표를 기다리는 중'}</div>
                </div>
              `;
            }).join('')
          : options.map((opt)=>{
              const optionId = opt?.id || '';
              const label = typeof opt === 'string' ? opt : (opt?.text || '');
              if(!optionId || !label) return '';
              return `<button class="poll-option" type="button" data-poll-option data-option-id="${escapeHtml(optionId)}">${escapeHtml(label)}</button>`;
            }).join('');
        const footer = att.showResults
          ? `<div class="poll-footer muted">총 ${totalVotes}표${att.viewerSelection ? ' · 내 선택 표시됨' : ''}</div>`
          : `<div class="poll-footer muted">투표하면 결과가 공개됩니다</div>`;
        return `
          <div class="poll-card" data-poll-card data-state="${state}" data-post-id="${post.id}" data-poll-id="${pollId}">
            <div class="poll-question">${escapeHtml(att.question || '투표')}</div>
            <div class="poll-options ${att.showResults ? 'show-results' : 'vote-mode'}">
              ${optionHtml || '<div class="poll-empty">옵션이 없습니다</div>'}
            </div>
            ${footer}
          </div>
        `;
      }
      const url = att.url || '';
      if(!url) return '';
      if(att.type === 'video'){
        const safeUrl = escapeHtml(url);
        return `<figure class="media video" data-media-view="video" data-src="${safeUrl}"><video src="${safeUrl}" playsinline preload="metadata" muted></video><div class="media-overlay"><i class="ri-play-circle-line"></i></div></figure>`;
      }
      if(att.type === 'image'){
        const safeUrl = escapeHtml(url);
        return `<figure class="media image" data-media-view="image" data-src="${safeUrl}"><img src="${safeUrl}" alt="첨부 이미지"/><div class="media-overlay"><i class="ri-zoom-in-line"></i></div></figure>`;
      }
      const safeUrl = escapeHtml(url);
      const label = escapeHtml(att.filename || '첨부 파일');
      return `<a class="media file" href="${safeUrl}" target="_blank" rel="noopener">${label}</a>`;
    }).join('');
    return `<div class="post-media-grid">${items}</div>`;
  }

  document.addEventListener('click',(e)=>{
    const mediaEl = e.target.closest('[data-media-view]');
    if(!mediaEl) return;
    const src = mediaEl.getAttribute('data-src');
    const type = mediaEl.getAttribute('data-media-view');
    if(src){
      e.preventDefault();
      openMediaViewer(type, src);
    }
  });

  function commentHtml(c){
    const isGuest = c.authorType==='guest';
    const label = isGuest ? '익명' : (c.author?.handle || '@user');
    return `
      <div class="comment-row" data-comment-id="${c.id}" data-guest="${isGuest?'true':'false'}">
        <div class="avatar"></div>
        <div class="comment-bubble">
          <div class="comment-meta">${label} · ${timeAgo(c.createdAt)}</div>
          <div class="comment-text">${escapeHtml(c.text||'')}</div>
          <div class="comment-actions">
            <button class="pill" data-cmd="edit">수정</button>
            <button class="pill" data-cmd="delete">삭제</button>
          </div>
        </div>
      </div>
    `;
  }
  function renderPosts(){
    const root = $('#feedRoot .timeline');
    if(!root) return;
    const placeholder = $('#feedPlaceholder');
    // remove existing posts
    root.querySelectorAll('.post').forEach(el=> el.remove());
    if(!state.posts.length){
      if(placeholder){
        placeholder.classList.remove('hidden');
        const text = placeholder.querySelector('.placeholder-text');
        if(text) text.textContent = '아직 게시물이 없습니다. 첫 글을 남겨보세요!';
      }
      return;
    }
    if(placeholder) placeholder.classList.add('hidden');
    const html = state.posts.map(p=> postHtml(p)).join('');
    root.insertAdjacentHTML('beforeend', html);
    updateOwnerFlags();
    applyCommentLocks();
  }

  function applyCommentLocks(){
    const locked = isWriteLocked();
    $$('.comment-form').forEach((form)=>{
      const input = form.querySelector('input[name="comment"]');
      const button = form.querySelector('button[type="submit"]');
      if(locked){
        if(input){ input.disabled = true; input.placeholder = '현재는 관리자만 댓글 작성 가능'; }
        if(button) button.disabled = true;
        form.setAttribute('aria-disabled','true');
      }else{
        if(input){ input.disabled = false; input.placeholder = '댓글 달기…'; }
        if(button) button.disabled = false;
        form.removeAttribute('aria-disabled');
      }
    });
  }

  function updateOwnerFlags(){
    const posts = state.posts || [];
    const currentUserId = state.session?.user?.id || null;
    posts.forEach((post)=>{
      post.isOwner = !!(currentUserId && post.author && post.author.id === currentUserId);
    });
    const articles = document.querySelectorAll('.post');
    articles.forEach((article)=>{
      const postId = article.getAttribute('data-post-id');
      const post = posts.find((p)=> p.id === postId);
      article.dataset.owner = post?.isOwner ? 'true' : 'false';
    });
    refreshPostAvatars();
  }

  function refreshPostAvatars(){
    const posts = state.posts || [];
    document.querySelectorAll('.post').forEach((article)=>{
      const postId = article.getAttribute('data-post-id');
      const post = posts.find((p)=> p.id === postId);
      const author = resolveAuthorForDisplay(post?.author || null);
      const avatarEl = article.querySelector('.avatar');
      const fallbackAuthor = post?.author || {};
      setAvatarBackground(avatarEl, author, fallbackAuthor.handle || fallbackAuthor.name || '@user');
      article.querySelectorAll('.comment-row').forEach((row)=>{
        const commentId = row.getAttribute('data-comment-id');
        const comment = post?.comments?.find((c)=> c.id === commentId);
        const commentAuthor = resolveAuthorForDisplay(comment?.author || null);
        const commentAvatar = row.querySelector('.avatar');
        const fallbackComment = comment?.author || {};
        const fallbackLabel = fallbackComment.handle || fallbackComment.name || (comment?.authorType === 'guest' ? 'Guest' : '@user');
        setAvatarBackground(commentAvatar, commentAuthor, fallbackLabel);
      });
    });
  }

  async function handlePollVote(btn){
    const card = btn.closest('[data-poll-card]');
    if(!card) return;
    if(card.dataset.state === 'results' || card.dataset.loading === 'true') return;
    const postId = card.getAttribute('data-post-id');
    const pollId = card.getAttribute('data-poll-id');
    const optionId = btn.getAttribute('data-option-id');
    if(!postId || !pollId || !optionId) return;
    card.dataset.loading = 'true';
    btn.disabled = true;
    btn.setAttribute('aria-busy','true');
    try{
      const res = await api(`/api/posts/${postId}/polls/${pollId}/vote`, {
        method:'POST',
        body:{ optionId },
      });
      const poll = res?.poll || null;
      if(!poll){
        await loadPosts();
        toast('투표가 완료되었습니다');
        return;
      }
      const idx = state.posts.findIndex((p)=> p.id === postId);
      if(idx >= 0){
        const updated = { ...state.posts[idx] };
        updated.attachments = (updated.attachments || []).map((att)=> (att && att.type === 'poll' && att.pollId === poll.pollId) ? poll : att);
        state.posts.splice(idx,1,updated);
        renderPosts();
      }else{
        await loadPosts();
      }
      toast('투표가 완료되었습니다');
    }catch(err){
      const msg = err?.message || '';
      if(msg.includes('already-voted')){
        toast('이미 이 투표에 참여했습니다');
      }else if(msg.includes('vote-not-allowed')){
        toast('투표할 수 있는 권한이 없습니다');
      }else if(msg.includes('poll-not-supported')){
        toast('현재 투표 기능을 이용할 수 없습니다');
      }else{
        toast('투표 실패: '+msg);
      }
      btn.disabled = false;
      btn.removeAttribute('aria-busy');
    }finally{
      btn.removeAttribute('aria-busy');
      delete card.dataset.loading;
    }
  }
  function timeAgo(iso){
    const t = new Date(iso).getTime(); const s = Math.floor((Date.now()-t)/1000);
    if(s<60) return `${s}초 전`; const m=Math.floor(s/60); if(m<60) return `${m}분 전`;
    const h=Math.floor(m/60); if(h<24) return `${h}시간 전`;
    const d=Math.floor(h/24); return `${d}일 전`;
  }
  function escapeHtml(s){ return (s||'').replace(/[&<>"]/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[m])); }
  function arrayBufferToBase64(buffer){
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const len = bytes.length;
    for(let i=0; i<len; i+=1){
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  function stringToBase64(str){
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let binary = '';
    bytes.forEach((b)=>{ binary += String.fromCharCode(b); });
    return btoa(binary);
  }
  function insertAtCursor(el, text){
    const start = el.selectionStart ?? el.value.length;
    const end = el.selectionEnd ?? el.value.length;
    const value = el.value || '';
    const before = value.slice(0, start);
    const after = value.slice(end);
    el.value = before + text + after;
    const pos = start + text.length;
    el.setSelectionRange(pos, pos);
    el.focus();
  }
  async function serializeAttachments(){
    const out = [];
    for(const att of state.attachments){
      if(att?.type === 'poll'){
        const payload = {
          question: att.data?.question || '',
          options: Array.isArray(att.data?.options) ? att.data.options : [],
        };
        const json = JSON.stringify(payload);
        out.push({
          type: 'poll',
          filename: `poll-${Date.now()}.json`,
          contentType: 'application/json',
          data: stringToBase64(json),
          meta: att.meta || payload,
          folder: 'polls',
        });
        continue;
      }
      if(att?.file){
        const buffer = await att.file.arrayBuffer();
        out.push({
          type: att.type,
          filename: att.file.name,
          contentType: att.file.type || 'application/octet-stream',
          data: arrayBufferToBase64(buffer),
          meta: att.meta || null,
          folder: 'posts',
        });
      }
    }
    return out;
  }

  // ===== Post compose
  on(btnPost,'click', async (e)=>{
    e.preventDefault();
    if(!state.session?.user){ openModal('#modal-login-post'); return; }
    if(isWriteLocked()){ toast('현재는 관리자만 게시물을 작성할 수 있습니다.'); return; }
    const text = (composerText?.value||'').trim();
    if(!text && state.attachments.length===0){ toast('내용 또는 미디어를 추가해 주세요'); return; }
    try{
      const attachmentsPayload = await serializeAttachments();
      await api('/api/posts',{ method:'POST', body:{ text, attachments: attachmentsPayload }});
      toast('게시되었습니다');
      if(composerText) composerText.value='';
      clearAttachments();
      await loadPosts();
    }catch(err){
      if(String(err.message).includes('posting-restricted')){
        toast('현재는 관리자만 게시물을 작성할 수 있습니다.');
      }else{
        toast('게시 실패: '+err.message);
      }
    }
  });

  // ===== Comments: submit / edit / delete (서버 검증)
  document.addEventListener('submit', async (e)=>{
    const form = e.target.closest('.comment-form'); if(!form) return;
    e.preventDefault();
    const postId = form.getAttribute('data-post-id');
    const input = form.querySelector('input[name="comment"]');
    const text = (input?.value||'').trim(); if(!text) return;
    if(isWriteLocked()){ toast('현재는 관리자만 댓글을 작성할 수 있습니다.'); return; }

    // 회원이면 바로 등록
    if(state.session?.user){
      try{
        await api('/api/comments',{ method:'POST', body:{ postId, text }});
        input.value=''; await loadPosts();
      }catch(err){
        if(String(err.message).includes('posting-restricted')){
          toast('현재는 관리자만 댓글을 작성할 수 있습니다.');
        }else{
          toast('댓글 실패: '+err.message);
        }
      }
      return;
    }

    // 게스트: 서버 config 확인 + 1회 제한 서버가 판단
    if(!state.config.allowAnon){ openModal('#modal-login-post'); return; }
    openModal('#modal-guest-comment');
    const confirmBtn = $('#guestCommentConfirm'); const pwInput = $('#guestPw'); pwInput.value='';
    const onConfirm = async ()=>{
      const pw = pwInput.value.trim();
      if(!/^\d{4}$/.test(pw)){ toast('4자리 숫자 비밀번호를 입력하세요'); return; }
      try{
        await api('/api/comments',{ method:'POST', body:{ postId, text, guestPw: pw }});
        closeModal('#modal-guest-comment'); input.value=''; toast('댓글 등록됨');
        await loadPosts();
      }catch(err){
        closeModal('#modal-guest-comment');
        if(String(err.message).includes('guest-limit')) openModal('#modal-login-post');
        else if(String(err.message).includes('posting-restricted')) toast('현재는 관리자만 댓글을 작성할 수 있습니다.');
        else toast('댓글 실패: '+err.message);
      } finally {
        confirmBtn.removeEventListener('click', onConfirm);
      }
    };
    confirmBtn.addEventListener('click', onConfirm, { once:true });
  });

  function handleCommentAction(btn){
    const row = btn.closest('.comment-row'); if(!row) return;
    const cmd = btn.getAttribute('data-cmd');
    const commentId = row.getAttribute('data-comment-id');
    const isGuest = row.getAttribute('data-guest') === 'true';
    if(!commentId) return;
    if(cmd==='edit'){
      editTarget = { id: commentId, isGuest };
      const current = row.querySelector('.comment-text')?.textContent?.trim() || '';
      if(commentEditText) commentEditText.value = current;
      toggleHidden(commentEditPwRow, !(isGuest && !state.session?.user));
      if(commentEditPw) commentEditPw.value = '';
      openModal('#modal-comment-edit');
      return;
    }
    if(cmd==='delete'){
      deleteTarget = { id: commentId, isGuest };
      toggleHidden(commentDeletePwRow, !(isGuest && !state.session?.user));
      if(commentDeletePw) commentDeletePw.value = '';
      openModal('#modal-comment-delete');
    }
  }

  function handlePostMore(btn){
    const article = btn.closest('.post'); if(!article) return;
    const postId = article.getAttribute('data-post-id');
    if(!postId) return;
    const isOwner = article.getAttribute('data-owner') === 'true' || isOwnerPost(postId);
    postActionsTarget = { postId, isOwner };
    if(modalPostActions){
      modalPostActions.dataset.postId = postId;
      const targets = modalPostActions.querySelectorAll('[data-owner-only]');
      targets.forEach((el)=> toggleHidden(el, !isOwner));
      const reportRow = modalPostActions.querySelector('[data-post-action="report"]');
      if(reportRow){
        toggleHidden(reportRow, !state.session?.user);
      }
      openModal('#modal-post-actions');
    }
  }

  document.addEventListener('click', (e)=>{
    const followBtn = e.target.closest('[data-follow-handle]');
    if(followBtn){
      e.preventDefault();
      const handle = followBtn.getAttribute('data-follow-handle');
      const following = followBtn.getAttribute('data-following') === 'true';
      handleFollowToggle(handle, following);
      return;
    }
    const trendItem = e.target.closest('[data-trend-tag]');
    if(trendItem && trendItem.dataset.trendTag){
      e.preventDefault();
      goToExploreTag(trendItem.dataset.trendTag);
      return;
    }
    const dmBtn = e.target.closest('[data-dm]');
    if(dmBtn && dmBtn.dataset.dm){
      e.preventDefault();
      openDirectMessage(dmBtn.dataset.dm);
      return;
    }
    const profileEl = e.target.closest('[data-profile-handle]');
    if(profileEl){
      const handle = profileEl.getAttribute('data-profile-handle');
      if(handle){
        e.preventDefault();
        navigateToProfile(handle);
        return;
      }
    }
    const closeBtn = e.target.closest('[data-close]');
    if(closeBtn){
      const targetSel = closeBtn.getAttribute('data-close');
      if(targetSel==='#modal-comment-edit') editTarget = null;
      if(targetSel==='#modal-comment-delete') deleteTarget = null;
      if(targetSel==='#modal-post-actions') postActionsTarget = null;
      if(targetSel==='#modal-post-edit') postEditTarget = null;
      if(targetSel==='#modal-post-delete') postDeleteTarget = null;
      if(targetSel==='#modal-report') reportTarget = null;
      if(targetSel==='#modal-media-viewer') resetMediaViewer();
      if(targetSel==='#modal-poll') pollForm?.reset();
    }
    const goLoginBtn = e.target.closest('[data-go="login"]');
    if(goLoginBtn){
      e.preventDefault();
      closeModal(goLoginBtn);
      location.href = 'auth.html';
      return;
    }
    const pollBtn = e.target.closest('[data-poll-option]');
    if(pollBtn){
      e.preventDefault();
      handlePollVote(pollBtn);
      return;
    }
    const cmdBtn = e.target.closest('[data-cmd]');
    if(cmdBtn){
      e.preventDefault();
      handleCommentAction(cmdBtn);
      return;
    }
    const moreBtn = e.target.closest('[data-action="more"]');
    if(moreBtn){
      e.preventDefault();
      handlePostMore(moreBtn);
    }
  });

  document.addEventListener('keydown',(e)=>{
    if(e.key !== 'Enter' && e.key !== ' ') return;
    const trendItem = e.target.closest('[data-trend-tag]');
    if(trendItem && trendItem.dataset.trendTag){
      e.preventDefault();
      goToExploreTag(trendItem.dataset.trendTag);
    }
  });

  on(commentEditForm,'submit', async (e)=>{
    e.preventDefault();
    if(!editTarget) return;
    const text = (commentEditText?.value || '').trim();
    if(!text){ toast('내용을 입력하세요'); return; }
    const body = { text };
    if(editTarget.isGuest && !state.session?.user){
      const pw = (commentEditPw?.value || '').trim();
      if(!/^\d{4}$/.test(pw)){ toast('4자리 숫자를 입력하세요'); return; }
      body.guestPw = pw;
    }
    try{
      await api(`/api/comments/${editTarget.id}`, { method:'PUT', body });
      toast('댓글을 수정했어요');
      closeModal('#modal-comment-edit');
      editTarget = null;
      await loadPosts();
    }catch(err){
      toast('수정 실패: '+err.message);
    }
  });

  on(commentDeleteForm,'submit', async (e)=>{
    e.preventDefault();
    if(!deleteTarget) return;
    const body = {};
    if(deleteTarget.isGuest && !state.session?.user){
      const pw = (commentDeletePw?.value || '').trim();
      if(!/^\d{4}$/.test(pw)){ toast('4자리 숫자를 입력하세요'); return; }
      body.guestPw = pw;
    }
    try{
      await api(`/api/comments/${deleteTarget.id}`, { method:'DELETE', body });
      toast('댓글을 삭제했어요');
      closeModal('#modal-comment-delete');
      deleteTarget = null;
      await loadPosts();
    }catch(err){
      toast('삭제 실패: '+err.message);
    }
  });

  on(postEditForm,'submit', async (e)=>{
    e.preventDefault();
    const target = postEditTarget;
    if(!target) return;
    const text = (postEditText?.value || '').trim();
    if(!text && !target.hasAttachments){
      toast('게시물 내용을 입력하세요');
      return;
    }
    try{
      await api(`/api/posts/${target.id}`, { method:'PUT', body:{ text } });
      toast('게시물을 수정했어요');
      closeModal('#modal-post-edit');
      postEditTarget = null;
      await loadPosts();
    }catch(err){
      toast('수정 실패: '+err.message);
    }
  });

  on(postDeleteForm,'submit', async (e)=>{
    e.preventDefault();
    if(!postDeleteTarget) return;
    try{
      await api(`/api/posts/${postDeleteTarget}`, { method:'DELETE' });
      toast('게시물을 삭제했어요');
      closeModal('#modal-post-delete');
      postDeleteTarget = null;
      await loadPosts();
    }catch(err){
      toast('삭제 실패: '+err.message);
    }
  });

  on(reportForm,'submit', async (e)=>{
    e.preventDefault();
    if(!reportTarget) return;
    const postId = reportTarget.postId;
    const reasonVal = (reportReason?.value || '').trim();
    const detailVal = (reportDetail?.value || '').trim();
    if(!reasonVal){
      toast('신고 사유를 선택하세요');
      return;
    }
    if(reasonVal === 'other' && detailVal.length < 5){
      toast('자세한 설명을 5자 이상 입력해 주세요');
      return;
    }
    try{
      await api(`/api/posts/${postId}/report`, {
        method:'POST',
        body:{ reason: reasonVal, detail: detailVal },
      });
      toast('신고가 접수되었습니다');
      if(reportForm) reportForm.reset();
      if(reportReason) reportReason.value = '';
      if(reportDetail) reportDetail.value = '';
      if(window.LoomaSelect && typeof window.LoomaSelect.set === 'function'){
        window.LoomaSelect.set('reportReason', '');
      }
      closeModal('#modal-report');
      reportTarget = null;
    }catch(err){
      const msg = err?.message || '';
      if(msg.includes('report-not-supported')){
        toast('현재 신고 기능을 사용할 수 없습니다');
      }else{
        toast('신고 실패: '+msg);
      }
    }
  });

  on(postActionsList,'click', async (e)=>{
    const btn = e.target.closest('[data-post-action]'); if(!btn) return;
    e.preventDefault();
    if(!postActionsTarget){ closeModal('#modal-post-actions'); return; }
    const { postId, isOwner } = postActionsTarget;
    const action = btn.getAttribute('data-post-action');
    const link = `${location.origin}${location.pathname}?post=${encodeURIComponent(postId)}`;

    if(action==='copy-link'){
      try{
        if(navigator.clipboard?.writeText){
          await navigator.clipboard.writeText(link);
        }else{
          const tmp=document.createElement('textarea');
          tmp.value=link;
          tmp.setAttribute('readonly','readonly');
          tmp.style.position='absolute';
          tmp.style.left='-9999px';
          document.body.appendChild(tmp);
          tmp.select();
          document.execCommand('copy');
          tmp.remove();
        }
        toast('링크를 복사했습니다');
      }catch(err){
        toast('주소를 직접 복사해 주세요: '+link);
      }
      closeModal('#modal-post-actions');
      postActionsTarget = null;
      return;
    }

    if(action==='share'){
      let shared = false;
      if(navigator.share){
        try{
          await navigator.share({ url: link });
          shared = true;
        }catch(err){
          if(err && err.name === 'AbortError') shared = true; // 사용자 취소는 조용히 통과
        }
      }
      if(!shared) toast('이 브라우저에서는 공유 기능을 사용할 수 없습니다');
      closeModal('#modal-post-actions');
      postActionsTarget = null;
      return;
    }

    if(action==='report'){
      if(!state.session?.user){
        toast('신고는 로그인 후 이용할 수 있습니다');
        closeModal('#modal-post-actions');
        return;
      }
      closeModal('#modal-post-actions');
      postActionsTarget = null;
      reportTarget = { postId };
      if(reportForm){
        reportForm.reset();
        if(reportReason) reportReason.value = '';
        if(reportDetail) reportDetail.value = '';
        if(window.LoomaSelect && typeof window.LoomaSelect.set === 'function'){
          window.LoomaSelect.set('reportReason', '');
        }
      }
      openModal('#modal-report');
      return;
    }

    if(action==='edit'){
      closeModal('#modal-post-actions');
      postActionsTarget = null;
      if(!isOwner){
        toast('게시물 수정 권한이 없습니다');
        return;
      }
      const article = document.querySelector(`.post[data-post-id="${postId}"]`);
      const current = article?.querySelector('.post-text')?.textContent?.trim() || '';
      if(postEditText) postEditText.value = current;
      const postData = state.posts.find((p)=> p.id === postId);
      postEditTarget = { id: postId, hasAttachments: !!(postData?.attachments?.length) };
      openModal('#modal-post-edit');
      return;
    }

    if(action==='delete'){
      closeModal('#modal-post-actions');
      postActionsTarget = null;
      if(!isOwner){
        toast('게시물 삭제 권한이 없습니다');
        return;
      }
      postDeleteTarget = postId;
      openModal('#modal-post-delete');
      return;
    }
  });

  // ===== Mobile dock pad
  (function dockPad(){
    const mq = matchMedia('(max-width:1023.98px)'); const tl=$('.timeline');
    const apply = ()=> mq.matches ? tl?.classList.add('with-dock-pad') : tl?.classList.remove('with-dock-pad');
    apply(); mq.addEventListener('change', apply);
  })();

  // ===== Init
  loadInitial().catch(err=> toast('초기 로딩 실패: '+err.message));
})();
