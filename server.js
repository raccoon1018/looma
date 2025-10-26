// 최소 단일 서버 파일 (CommonJS) — Node 18+ 권장
// 정적 서빙 + API (세션/쿠키, 글/댓글, 익명 1회 댓글 + 4자리 비번 검증)
// 실행: node server.js → http://localhost:3000

require('dotenv').config();

const http = require('http');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const crypto = require('crypto');
const url = require('url');
const createStore = require('./store');
const { uploadToStorage } = require('./r2');

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const ADMIN_KEY = process.env.LOOMA_ADMIN_KEY || 'dev';
const __dirnameResolved = __dirname; // CommonJS에서는 바로 사용 가능
const DB_PATH = path.join(__dirnameResolved, 'server.db.json');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

const SUPER_ADMIN_HANDLES = new Set(['@nuguls', '@looma_owner']);
const ADMIN_FLAG_KEYWORDS = new Set([
  'admin',
  'administrator',
  'moderator',
  'manager',
  'owner',
  'staff',
  'operator',
  'maintainer',
  'superadmin',
]);
const ADMIN_FLAG_BLACKLIST = new Set(['authenticated', 'user', 'member', 'basic']);
const SUPERADMIN_FLAG_KEYWORDS = new Set(['superadmin', 'owner', 'root', 'founder']);
const SUPERADMIN_DEMOTE_PIN = process.env.LOOMA_SUPERADMIN_PIN || '1018';
const DEFAULT_TEMP_PASSWORD = process.env.LOOMA_TEMP_PASSWORD || '123456789a!';

function send(res, code, body, headers = {}) {
  res.writeHead(code, {
    'Cache-Control': 'no-store',
    'Content-Type': 'text/plain; charset=utf-8',
    ...headers,
  });
  res.end(body);
}
function sendJSON(res, code, obj, headers={}) {
  send(res, code, JSON.stringify(obj), { 'Content-Type':'application/json; charset=utf-8', ...headers });
}
function parseBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); }
    });
  });
}
function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  raw.split(';').forEach(p=>{
    const i = p.indexOf('='); if(i<0) return;
    const k = p.slice(0,i).trim(); const v = decodeURIComponent(p.slice(i+1));
    if(k) out[k]=v;
  });
  return out;
}
function setCookie(res, name, val, opts={}) {
  const parts = [`${name}=${encodeURIComponent(val)}`];
  if (opts.path) parts.push(`Path=${opts.path}`);
  if (opts.httpOnly) parts.push('HttpOnly');
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.secure) parts.push('Secure');
  res.setHeader('Set-Cookie', [...(res.getHeader('Set-Cookie')||[]), parts.join('; ')]);
}
function uid(n=16){ return crypto.randomBytes(n).toString('hex'); }
function sha256(s){ return crypto.createHash('sha256').update(String(s)).digest('hex'); }

function hasValidAdminKey(req) {
  const header = req.headers['x-admin-key'];
  return header === ADMIN_KEY;
}

function parseRelativeDuration(value) {
  if (!value) return null;
  const match = String(value).trim().match(/^([0-9]+)([dhm])$/i);
  if (!match) return null;
  const amount = Number(match[1]);
  if (!Number.isFinite(amount) || amount <= 0) return null;
  const unit = match[2].toLowerCase();
  const multipliers = { d: 86400000, h: 3600000, m: 60000 };
  const millis = multipliers[unit] ? amount * multipliers[unit] : null;
  return Number.isFinite(millis) && millis > 0 ? millis : null;
}

function toHandleLower(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function collectRoleFlags(user) {
  if (!user) return [];
  const flags = new Set();
  const push = (value) => {
    if (value === undefined || value === null) return;
    const str = String(value).trim().toLowerCase();
    if (!str) return;
    flags.add(str);
  };
  const arrays = [user.roles, user.capabilities, user.tags, user.privileges, user.scopes];
  arrays.forEach((list) => {
    if (Array.isArray(list)) list.forEach(push);
  });
  [
    user.role,
    user.adminRole,
    user.accountRole,
    user.adminLevel,
    user.tier,
    user.type,
  ].forEach(push);
  if (user.isAdmin === true || user.admin === true) push('admin');
  if (user.isSuperAdmin === true || user.superadmin === true) push('superadmin');
  if (user.isOwner === true || user.owner === true) push('owner');
  return Array.from(flags);
}

function isSuperAdminUser(user) {
  if (!user) return false;
  const id = String(user.id || '').toLowerCase();
  if (id === 'u1') return true;
  const handle = toHandleLower(user.handle);
  if (handle && SUPER_ADMIN_HANDLES.has(handle)) return true;
  const roles = collectRoleFlags(user);
  if (roles.some((role) => SUPERADMIN_FLAG_KEYWORDS.has(role))) return true;
  return false;
}

function isAdminUser(user) {
  if (!user) return false;
  if (isSuperAdminUser(user)) return true;
  const roles = collectRoleFlags(user);
  return roles.some((role) => {
    if (!role || ADMIN_FLAG_BLACKLIST.has(role)) return false;
    if (ADMIN_FLAG_KEYWORDS.has(role)) return true;
    const tokens = role.split(/[^a-z0-9]+/).filter(Boolean);
    return tokens.some((token) => ADMIN_FLAG_KEYWORDS.has(token));
  });
}

function withSuperAdminMeta(user) {
  if (!user) return null;
  if (!isSuperAdminUser(user)) return user;
  return {
    ...user,
    role: 'superadmin',
    isSuperAdmin: true,
  };
}

function normalizeEmail(raw){
  const email = String(raw || '').trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}
function normalizePhone(raw){
  const digits = String(raw || '').replace(/\D/g, '');
  if (digits.length !== 11 || !digits.startsWith('010')) return null;
  return `010-${digits.slice(3,7)}-${digits.slice(7)}`;
}
function normalizeHandle(raw){
  if (!raw) return null;
  let handle = String(raw).trim();
  if (!handle.startsWith('@')) handle = '@' + handle;
  handle = '@' + handle.slice(1).toLowerCase();
  return /^@[a-z0-9_]{3,}$/.test(handle) ? handle : null;
}
function validatePasswordStrength(pw){
  return (
    typeof pw === 'string' &&
    pw.length >= 8 &&
    /[a-z]/.test(pw) &&
    /[A-Z]/.test(pw) &&
    /\d/.test(pw) &&
    /[^A-Za-z0-9]/.test(pw)
  );
}
const EXT_BY_MIME = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
  'image/gif': '.gif',
  'video/mp4': '.mp4',
  'video/quicktime': '.mov',
  'video/webm': '.webm',
};
function detectExtension(filename, contentType){
  const fromName = filename ? path.extname(filename).toLowerCase() : '';
  if (fromName) return fromName;
  return EXT_BY_MIME[contentType] || '';
}
const MEDIA_MAX_BYTES = Number(process.env.LOOMA_MEDIA_MAX_BYTES || 10 * 1024 * 1024);

async function saveBinaryToStorage({ folder, filename, base64, contentType }){
  if(!base64) return null;
  let buffer;
  try{
    buffer = Buffer.from(base64, 'base64');
  }catch{
    return null;
  }
  if(buffer.length > MEDIA_MAX_BYTES){
    throw Object.assign(new Error('file-too-large'), { code:'file-too-large' });
  }
  const ext = detectExtension(filename, contentType) || '';
  const key = `${folder}/${Date.now()}-${uid(6)}${ext}`;
  const stored = await uploadToStorage({ key, buffer, contentType });
  return {
    url: stored?.url || null,
    size: buffer.length,
    contentType: contentType || 'application/octet-stream',
    key,
    ext,
  };
}

async function prepareAttachments(list){
  if(!Array.isArray(list)) return [];
  const attachments = [];
  for(const item of list){
    const type = item?.type || 'file';
    if(type === 'poll'){
      const pollMeta = item?.meta || {};
      let question = String(pollMeta.question || '').trim();
      let options = Array.isArray(pollMeta.options) ? pollMeta.options : [];
      options = options.map((opt)=> String(opt || '').trim()).filter(Boolean);
      if((!question || options.length < 2) && item?.data){
        try{
          const decoded = JSON.parse(Buffer.from(item.data, 'base64').toString('utf8'));
          if(!question) question = String(decoded?.question || '').trim();
          if(options.length < 2 && Array.isArray(decoded?.options)){
            options = decoded.options.map((opt)=> String(opt || '').trim()).filter(Boolean);
          }
        }catch{/* ignore parse errors */}
      }
      if(!question || options.length < 2){
        throw Object.assign(new Error('poll-invalid'), { code:'poll-invalid' });
      }
      attachments.push({
        type: 'poll',
        question,
        options,
      });
      continue;
    }
    if(item && item.data){
      try{
        const folder = item.folder || (item.type === 'poll' ? 'polls' : 'posts');
        const stored = await saveBinaryToStorage({
          folder,
          filename: item.filename || `${item.type || 'file'}`,
          base64: item.data,
          contentType: item.contentType || 'application/octet-stream',
        });
        attachments.push({
          type: item.type || 'file',
          url: stored?.url,
          contentType: item.contentType || stored?.contentType || null,
          size: stored?.size || null,
          filename: item.filename || null,
          meta: item.meta || null,
          key: stored?.key || item.key || null,
          ext: stored?.ext || null,
        });
      }catch(err){
        if(err && err.code === 'file-too-large') throw err;
        throw Object.assign(new Error('attachment-invalid'), { code:'attachment-invalid' });
      }
    }else if(item && item.url){
      attachments.push({
        type: item.type || 'file',
        url: item.url,
        contentType: item.contentType || null,
        size: item.size || null,
        filename: item.filename || null,
        meta: item.meta || null,
        key: item.key || null,
        ext: item.ext || null,
      });
    }
  }
  return attachments;
}

function presentPostForClient(post, { userId, cid }) {
  if (!post) return null;
  if (store && typeof store.presentPost === 'function') {
    return store.presentPost(post, { viewerUserId: userId || null, viewerCid: cid || null });
  }
  return post;
}

function presentPostsForClient(posts, ctx) {
  if (!Array.isArray(posts)) return [];
  return posts
    .map((post) => presentPostForClient(post, ctx))
    .filter((post) => !!post);
}

function presentPollFromPost(post, pollId, ctx) {
  const presented = presentPostForClient(post, ctx || {});
  if (!presented) return null;
  return (presented.attachments || []).find(
    (att) => att && att.type === 'poll' && att.pollId === pollId,
  ) || null;
}

function mapMessageError(err) {
  if (!err) return { status: 500, payload: { error: 'messages-error' } };
  const code = err.code || 'messages-error';
  const message = err.message || '';
  const payload = { error: code };
  if (message) payload.message = message;
  switch (code) {
    case 'auth-required':
      return { status: 401, payload };
    case 'access-denied':
      return { status: 403, payload };
    case 'channel-not-found':
    case 'user-not-found':
      return { status: 404, payload };
    case 'invalid-input':
    case 'invalid-target':
    case 'channel-required':
    case 'text-required':
    case 'handle-invalid':
    case 'invalid-name':
    case 'not-member':
      return { status: 400, payload };
    case 'duplicate-name':
      return { status: 409, payload };
    case 'messages-disabled':
      return { status: 501, payload };
    case 'profile-disabled':
      return { status: 501, payload };
    default:
      return { status: 500, payload };
  }
}

const store = createStore({ dbPath: DB_PATH, uid, sha256 });
const storeReady = (typeof store.ensureReady === 'function') ? store.ensureReady() : Promise.resolve();

async function resolveUserForAdminTarget(payload){
  if(!payload || typeof payload !== 'object') return null;
  const idCandidate = payload.userId || payload.id;
  if(idCandidate && typeof store.getUserProfile === 'function'){
    const profile = await store.getUserProfile(String(idCandidate));
    if(profile && profile.id) return profile;
  }
  const handleRaw = payload.handle || payload.username || payload.user;
  if(handleRaw && typeof store.findUserByHandle === 'function'){
    const normalized = normalizeHandle(handleRaw);
    if(normalized){
      const user = await store.findUserByHandle(normalized);
      if(user && user.id){
        if(typeof store.getUserProfile === 'function'){
          const profile = await store.getUserProfile(user.id);
          if(profile && profile.id) return profile;
        }
        if(typeof store.publicUser === 'function'){
          const publicView = store.publicUser(user);
          if(publicView && publicView.id) return publicView;
        }
        return user;
      }
    }
  }
  const emailRaw = payload.email || payload.userEmail;
  if(emailRaw && typeof store.findUserByEmail === 'function'){
    const normalizedEmail = normalizeEmail(emailRaw);
    if(normalizedEmail){
      const user = await store.findUserByEmail(normalizedEmail);
      if(user && user.id){
        if(typeof store.getUserProfile === 'function'){
          const profile = await store.getUserProfile(user.id);
          if(profile && profile.id) return profile;
        }
        if(typeof store.publicUser === 'function'){
          const publicView = store.publicUser(user);
          if(publicView && publicView.id) return publicView;
        }
        return user;
      }
    }
  }
  const phoneRaw = payload.phone || payload.phoneNumber;
  if(phoneRaw && typeof store.findUserByPhone === 'function'){
    const normalizedPhone = normalizePhone(phoneRaw);
    if(normalizedPhone){
      const user = await store.findUserByPhone(normalizedPhone);
      if(user && user.id){
        if(typeof store.getUserProfile === 'function'){
          const profile = await store.getUserProfile(user.id);
          if(profile && profile.id) return profile;
        }
        if(typeof store.publicUser === 'function'){
          const publicView = store.publicUser(user);
          if(publicView && publicView.id) return publicView;
        }
        return user;
      }
    }
  }
  return null;
}

// ===== Static
async function serveStatic(req, res, pathname){
  let filePath = path.join(__dirnameResolved, pathname);
  try {
    const st = await fsp.stat(filePath);
    if (st.isDirectory()) filePath = path.join(filePath, 'home.html');
  } catch {
    if (pathname === '/' || pathname === '') filePath = path.join(__dirnameResolved, 'home.html');
  }
  try {
    const ext = path.extname(filePath).toLowerCase();
    const data = await fsp.readFile(filePath);
    send(res, 200, data, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
  } catch {
    send(res, 404, 'Not Found');
  }
}

// ===== Router
const server = http.createServer(async (req, res) => {
  try{
    const u = new URL(req.url, `http://${req.headers.host}`);
    const pathname = decodeURIComponent(u.pathname);
    const method = req.method || 'GET';
    const cookies = parseCookies(req);

    // Create client id cookie (for guest once-limit)
    let cid = cookies['cid'];
    if(!cid){ cid = uid(8); setCookie(res,'cid',cid,{ path:'/', httpOnly:false, sameSite:'Lax', maxAge:60*60*24*365*2 }); }

    // CORS preflight (not strictly needed same-origin)
    if(method==='OPTIONS'){
      res.writeHead(200, {
        'Access-Control-Allow-Origin':'*',
        'Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers':'Content-Type,X-Admin-Key',
      }); return res.end();
    }

    await storeReady;

    const adminKeyValid = hasValidAdminKey(req);
    async function hasAdminSession() {
      const sid = cookies['sid'];
      if(!sid) return false;
      try{
        const sessionUser = await store.getSessionUser(sid);
        return isAdminUser(sessionUser);
      }catch(err){
        return false;
      }
    }
    let cachedAdminAllowed = null;
    async function adminAllowed(){
      if(adminKeyValid) return true;
      if(cachedAdminAllowed !== null) return cachedAdminAllowed;
      cachedAdminAllowed = await hasAdminSession();
      return cachedAdminAllowed;
    }
    async function getSuperAdminSession(){
      const sid = cookies['sid'];
      if(!sid) return null;
      try{
        const sessionUser = await store.getSessionUser(sid);
        if(isSuperAdminUser(sessionUser)) return sessionUser;
      }catch(_){}
      return null;
    }
    async function isChatRestrictedFor(user){
      if(!user) return true;
      try{
        const config = await store.getConfig();
        return !!config?.chatRestricted && !isAdminUser(user);
      }catch(err){
        console.error('config load failed', err);
        return false;
      }
    }
    async function enforceChatAvailability(user){
      if(await isChatRestrictedFor(user)){
        sendJSON(res,403,{ error:'chat-restricted', message:'현재 채팅 기능이 일시 중단되었습니다.' });
        return true;
      }
      return false;
    }

    // ---- API routes
    if(pathname==='/api/health') return sendJSON(res,200,{ok:true});
    if(pathname==='/api/config' && method==='GET'){
      const config = await store.getConfig();
      return sendJSON(res,200,config);
    }
    if(pathname==='/api/config' && method==='POST'){
      const key = req.headers['x-admin-key'];
      if(key!==ADMIN_KEY) return sendJSON(res,403,{error:'forbidden'});
      const body = await parseBody(req);
      const payload = {};
      if(body.allowAnon !== undefined) payload.allowAnon = !!body.allowAnon;
      if(body.basicPostingRestricted !== undefined) payload.basicPostingRestricted = !!body.basicPostingRestricted;
      const config = await store.updateConfig(payload);
      return sendJSON(res,200,{saved:true,config});
    }

    if(pathname==='/api/admin/system' && method==='GET'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      const config = await store.getConfig();
      const codes = typeof store.listReferralCodes === 'function' ? await store.listReferralCodes() : [];
      return sendJSON(res,200,{ config, referralCodes: codes });
    }
    if(pathname==='/api/admin/system' && method==='POST'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      const body = await parseBody(req);
      const payload = {};
      if(body.allowAnon !== undefined) payload.allowAnon = !!body.allowAnon;
      if(body.basicPostingRestricted !== undefined) payload.basicPostingRestricted = !!body.basicPostingRestricted;
      if(typeof body.regMode === 'string') payload.registrationMode = body.regMode === 'invite' ? 'invite' : 'open';
      if(typeof body.registrationMode === 'string') payload.registrationMode = body.registrationMode === 'invite' ? 'invite' : 'open';
      if(body.requiresReferralCode !== undefined) payload.requiresReferralCode = !!body.requiresReferralCode;
      const config = await store.updateConfig(payload);
      const codes = typeof store.listReferralCodes === 'function' ? await store.listReferralCodes() : [];
      return sendJSON(res,200,{ ok:true, config, referralCodes: codes });
    }

    if(pathname==='/api/admin/chat/channels' && method==='GET'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      const superSession = await getSuperAdminSession();
      if(!superSession) return sendJSON(res,403,{ error:'forbidden' });
      if(typeof store.adminListMessageChannels !== 'function') return sendJSON(res,501,{ error:'chat-monitor-not-supported' });
      try{
        const items = await store.adminListMessageChannels();
        return sendJSON(res,200,{ items: Array.isArray(items) ? items : [] });
      }catch(err){
        console.error('admin chat channel list error', err);
        const payload = err && err.code ? { error: err.code, message: err.message } : { error:'chat-monitor-error' };
        const status = err && err.code === 'channel-not-found' ? 404 : (err && err.code === 'access-denied' ? 403 : 500);
        return sendJSON(res,status,payload);
      }
    }
    const adminChatChannelMatch = pathname.match(/^\/api\/admin\/chat\/channels\/([^/]+)$/);
    if(adminChatChannelMatch && method==='GET'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      const superSession = await getSuperAdminSession();
      if(!superSession) return sendJSON(res,403,{ error:'forbidden' });
      if(typeof store.adminListChannelMessages !== 'function') return sendJSON(res,501,{ error:'chat-monitor-not-supported' });
      const channelId = decodeURIComponent(adminChatChannelMatch[1]);
      const limitParam = Number(u.searchParams.get('limit') || '0');
      const limit = Number.isFinite(limitParam) && limitParam > 0 ? limitParam : undefined;
      try{
        const data = await store.adminListChannelMessages(channelId, { limit });
        if(!data || !data.channel) return sendJSON(res,404,{ error:'channel-not-found' });
        return sendJSON(res,200,data);
      }catch(err){
        console.error('admin chat channel detail error', err);
        if(err && err.code === 'channel-not-found') return sendJSON(res,404,{ error:err.code, message:err.message });
        if(err && err.code === 'access-denied') return sendJSON(res,403,{ error:err.code, message:err.message });
        if(err && err.code === 'chat-monitor-not-supported') return sendJSON(res,501,{ error:err.code, message:err.message });
        if(err && err.code === 'channel-required') return sendJSON(res,400,{ error:err.code, message:err.message });
        const payload = err && err.code ? { error: err.code, message: err.message } : { error:'chat-monitor-error' };
        return sendJSON(res,500,payload);
      }
    }

    if(pathname==='/api/admin/reports' && method==='GET'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      if(typeof store.adminListReports !== 'function') return sendJSON(res,501,{ error:'reports-not-supported' });
      const q = (u.searchParams.get('q') || '').trim();
      const type = (u.searchParams.get('type') || '').trim();
      const status = (u.searchParams.get('status') || '').trim();
      try{
        const items = await store.adminListReports({
          query: q || undefined,
          type: type || undefined,
          status: status || undefined,
          limit: 300,
        });
        return sendJSON(res,200,{ items: Array.isArray(items) ? items : [] });
      }catch(err){
        const code = err?.code || 'report-list-failed';
        return sendJSON(res,500,{ error: code, message: err?.message || '신고 목록을 불러오지 못했습니다.' });
      }
    }

    if(pathname==='/api/admin/users' && method==='GET'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      if(typeof store.adminListUsers !== 'function') return sendJSON(res,501,{ error:'users-not-supported' });
      const q = (u.searchParams.get('q') || '').trim();
      const role = (u.searchParams.get('role') || '').trim();
      const status = (u.searchParams.get('status') || '').trim();
      const limitParam = Number(u.searchParams.get('limit') || '100');
      const limit = Number.isFinite(limitParam) && limitParam > 0 ? limitParam : 100;
      try{
        const items = await store.adminListUsers({
          query: q || undefined,
          role: role || undefined,
          status: status || undefined,
          limit,
        });
        return sendJSON(res,200,{ items: Array.isArray(items) ? items : [] });
      }catch(err){
        const code = err?.code || 'user-list-failed';
        return sendJSON(res,500,{ error: code, message: err?.message || '사용자 목록을 불러오지 못했습니다.' });
      }
    }

    if(pathname==='/api/admin/posts' && method==='GET'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      const q = (u.searchParams.get('q') || '').trim();
      const status = (u.searchParams.get('status') || '').trim();
      const limitParam = Number(u.searchParams.get('limit') || '100');
      const limit = Number.isFinite(limitParam) && limitParam > 0 ? limitParam : 100;
      try{
        let items = [];
        let adminError = null;
        if(typeof store.adminListPosts === 'function'){
          try{
            const fetched = await store.adminListPosts({
              query: q || undefined,
              status: status || undefined,
              limit,
            });
            if(Array.isArray(fetched)) items = fetched;
          }catch(err){
            adminError = err;
            console.error('adminListPosts failed', err);
          }
        }else{
          adminError = new Error('posts-not-supported');
        }
        const canFallback = typeof store.listPosts === 'function';
        if(canFallback && (adminError || (!items.length && !q && !status))){
          const fallbackPosts = await store.listPosts();
          const normalized = Array.isArray(fallbackPosts)
            ? fallbackPosts.map((post) => ({
                id: post.id,
                text: post.text || '',
                createdAt: post.createdAt || post.created_at || null,
                status: post.status || 'active',
                author: post.author
                  ? {
                      id: post.author.id,
                      handle: post.author.handle || null,
                      name: post.author.name || null,
                    }
                  : null,
              }))
            : [];
          if(normalized.length){
            items = normalized;
            adminError = null;
          }
        }
        if(adminError && !items.length){
          throw adminError;
        }
        if(q && items.length){
          const lower = q.toLowerCase();
          items = items.filter((item) => {
            const fields = [
              item.text,
              item.author?.handle,
              item.author?.name,
              item.id,
            ]
              .filter(Boolean)
              .map((val) => String(val).toLowerCase());
            return fields.some((field) => field.includes(lower));
          });
        }
        if(status && items.length){
          const desired = status.toLowerCase();
          items = items.filter((item) => (item.status || '').toLowerCase() === desired);
        }
        items = items
          .slice()
          .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
          .slice(0, Math.min(limit, 500));
        return sendJSON(res,200,{ items });
      }catch(err){
        const code = err?.code || 'post-list-failed';
        return sendJSON(res,500,{ error: code, message: err?.message || '게시물 목록을 불러오지 못했습니다.' });
      }
    }

    const adminPostDetailMatch = pathname.match(/^\/api\/admin\/posts\/([^/]+)$/);
    if(adminPostDetailMatch && method==='GET'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      if(typeof store.getPostById !== 'function') return sendJSON(res,501,{ error:'posts-not-supported' });
      const postId = adminPostDetailMatch[1];
      try{
        const post = await store.getPostById(postId);
        if(!post) return sendJSON(res,404,{ error:'post-not-found' });
        const presented = presentPostForClient(post, { userId: null, cid });
        const detail = presented ? { ...presented } : { ...post };
        detail.status = post.status || 'active';
        if(!detail.comments && Array.isArray(post.comments)) {
          detail.comments = post.comments;
        }
        return sendJSON(res,200,{ post: detail });
      }catch(err){
        console.error('admin post fetch failed', err);
        return sendJSON(res,500,{ error:'post-fetch-failed' });
      }
    }

    if(pathname==='/api/admin/refcodes' && method==='GET'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      if(typeof store.listReferralCodes !== 'function') return sendJSON(res,501,{ error:'referral-not-supported' });
      try{
        const codes = await store.listReferralCodes();
        return sendJSON(res,200,{ codes });
      }catch(err){
        console.error('refcode list error', err);
        if(err && err.code) return sendJSON(res,501,{ error: err.code, message: err.message });
        return sendJSON(res,500,{ error:'referral-list-failed' });
      }
    }
    if(pathname==='/api/admin/refcodes' && method==='POST'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      if(typeof store.createReferralCode !== 'function') return sendJSON(res,501,{ error:'referral-not-supported' });
      const body = await parseBody(req);
      const prefix = typeof body.prefix === 'string' ? body.prefix : '';
      let expiresIso = null;
      if(body.expiresAt){
        const parsed = new Date(body.expiresAt);
        if(Number.isFinite(parsed.getTime())) expiresIso = parsed.toISOString();
      }else if(body.expiresIn){
        const delta = parseRelativeDuration(body.expiresIn);
        if(delta) expiresIso = new Date(Date.now() + delta).toISOString();
      }
      const limitRaw = body.limit ?? body.usesLimit;
      let limit = null;
      if(limitRaw !== undefined && limitRaw !== null){
        if(String(limitRaw).trim().toLowerCase()==='unlimited') limit = 'unlimited';
        else{
          const num = Number(limitRaw);
          if(Number.isFinite(num) && num > 0) limit = num;
        }
      }
      try{
        const created = await store.createReferralCode({
          prefix,
          expiresAt: expiresIso,
          limit,
          notes: typeof body.notes === 'string' ? body.notes : null,
        });
        return sendJSON(res,200,{ ok:true, code: created });
      }catch(err){
        console.error('refcode create error', err);
        if(err && err.code) return sendJSON(res,501,{ error: err.code, message: err.message });
        return sendJSON(res,500,{ error:'referral-create-failed' });
      }
    }
    if(pathname==='/api/admin/refcodes/revoke' && method==='POST'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      if(typeof store.revokeReferralCode !== 'function') return sendJSON(res,501,{ error:'referral-not-supported' });
      const body = await parseBody(req);
      const code = String(body.code || body.referralCode || '').trim().toUpperCase();
      if(!code) return sendJSON(res,400,{ error:'code-required' });
      try{
        const ok = await store.revokeReferralCode(code);
        return sendJSON(res,200,{ ok });
      }catch(err){
        console.error('refcode revoke error', err);
        if(err && err.code) return sendJSON(res,501,{ error: err.code, message: err.message });
        return sendJSON(res,500,{ error:'referral-revoke-failed' });
      }
    }
    if(pathname==='/api/referrals/verify' && method==='POST'){
      if(typeof store.verifyReferralCode !== 'function') return sendJSON(res,501,{ error:'referral-not-supported' });
      const body = await parseBody(req);
      const code = String(body.code || body.referralCode || '').trim().toUpperCase();
      if(!code) return sendJSON(res,400,{ error:'code-required' });
      try{
        const result = await store.verifyReferralCode(code);
        return sendJSON(res,200,result);
      }catch(err){
        console.error('referral verify error', err);
        if(err && err.code) return sendJSON(res,501,{ error: err.code, message: err.message });
        return sendJSON(res,500,{ error:'referral-verify-failed' });
      }
    }

    if(pathname==='/api/admin/actions' && method==='POST'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      const body = await parseBody(req);
      const action = String(body.action || '').trim();
      if(!action) return sendJSON(res,400,{ error:'action-required' });
      const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
      const detail = typeof body.detail === 'string' ? body.detail.trim() : '';
      const reportId = body.reportId ? String(body.reportId).trim() : null;
      const userId = body.userId ? String(body.userId).trim() : null;
      const contentId = body.contentId ? String(body.contentId).trim() : null;
      const durationRaw = body.duration ? String(body.duration).trim() : null;
      let actorId = null;
      if(!adminKeyValid){
        const sid = cookies['sid'];
        if(sid){
          try{
            const sessionUser = await store.getSessionUser(sid);
            actorId = sessionUser?.id || null;
          }catch{/* ignore */}
        }
      }

      function resolveUntil(value){
        if(!value) return null;
        const rel = parseRelativeDuration(value);
        if(rel){
          return new Date(Date.now() + rel).toISOString();
        }
        const direct = new Date(value);
        if(Number.isFinite(direct.getTime())){
          return direct.toISOString();
        }
        return null;
      }

      async function resolveReport(statusValue){
        if(reportId && typeof store.adminResolveReport === 'function'){
          try{ await store.adminResolveReport(reportId, statusValue || 'closed'); }catch(err){ console.error('resolve report error', err); }
        }
      }

      let actionExtras = {};
      try{
        switch(action){
          case 'dismiss': {
            if(userId && typeof store.restoreAccount === 'function'){
              await store.restoreAccount(userId, {
                reason,
                detail,
                actorId,
                actorType: 'admin',
              });
            }
            if(reportId) await resolveReport('closed');
            if(userId && typeof store.logUserAction === 'function'){
              await store.logUserAction({
                userId,
                action: 'restored',
                reason: reason || null,
                detail: detail || null,
                actorId,
                actorType: 'admin',
              });
            }
            break;
          }
          case 'warn': {
            if(!userId) return sendJSON(res,400,{ error:'user-required' });
            if(typeof store.logUserAction === 'function'){
              await store.logUserAction({
                userId,
                action: 'warned',
                reason: reason || null,
                detail: detail || null,
                actorId,
                actorType: 'admin',
              });
            }
            if(reportId) await resolveReport('closed');
            break;
          }
          case 'delete-content': {
            if(!contentId) return sendJSON(res,400,{ error:'content-required' });
            if(typeof store.deletePost === 'function') await store.deletePost(contentId);
            if(userId && typeof store.logUserAction === 'function'){
              await store.logUserAction({
                userId,
                action: 'content-removed',
                reason: reason || null,
                detail: detail || null,
                actorId,
                actorType: 'admin',
                metadata: { contentId },
              });
            }
            if(reportId) await resolveReport('closed');
            break;
          }
          case 'suspend': {
            if(!userId) return sendJSON(res,400,{ error:'user-required' });
            const untilIso = resolveUntil(durationRaw);
            if(durationRaw && !untilIso) return sendJSON(res,400,{ error:'invalid-duration' });
            if(typeof store.suspendAccount === 'function'){
              await store.suspendAccount(userId, {
                reason,
                detail,
                until: untilIso,
                actorId,
                actorType: 'admin',
              });
            }
            if(reportId) await resolveReport('closed');
            break;
          }
          case 'ban': {
            if(!userId) return sendJSON(res,400,{ error:'user-required' });
            if(typeof store.banAccount === 'function'){
              await store.banAccount(userId, {
                reason,
                detail,
                actorId,
                actorType: 'admin',
              });
            }else if(typeof store.suspendAccount === 'function'){
              await store.suspendAccount(userId, {
                reason,
                detail,
                until: null,
                actorId,
                actorType: 'admin',
              });
            }
            if(reportId) await resolveReport('closed');
            break;
          }
          case 'deactivate': {
            if(!userId) return sendJSON(res,400,{ error:'user-required' });
            if(typeof store.deactivateAccount === 'function'){
              await store.deactivateAccount(userId, {
                reason,
                detail,
                actorId,
                actorType: 'admin',
              });
            }
            if(reportId) await resolveReport('closed');
            break;
          }
          case 'make-admin': {
            if(!userId) return sendJSON(res,400,{ error:'user-required' });
            if(typeof store.setUserRole === 'function') await store.setUserRole(userId, 'admin');
            if(typeof store.logUserAction === 'function'){
              await store.logUserAction({
                userId,
                action: 'promoted-admin',
                reason: reason || null,
                detail: detail || null,
                actorId,
                actorType: 'admin',
              });
            }
            break;
          }
          case 'remove-admin': {
            if(!userId) return sendJSON(res,400,{ error:'user-required' });
            let targetProfile = null;
            if(typeof store.getUserProfile === 'function'){
              try{
                targetProfile = await store.getUserProfile(userId);
              }catch(err){
                if(err?.code !== 'user-not-found'){
                  console.error('fetch target user failed', err);
                }
              }
            }
            const targetIsSuper = isSuperAdminUser(targetProfile);
            if(targetIsSuper){
              const submittedPin = String(body.pin || body.passcode || '').trim();
              if(submittedPin !== SUPERADMIN_DEMOTE_PIN){
                const errCode = submittedPin ? 'superadmin-pin-invalid' : 'superadmin-pin-required';
                return sendJSON(res,403,{ error: errCode, message:'슈퍼관리자 PIN이 일치하지 않습니다.' });
              }
            }
            if(typeof store.setUserRole === 'function') await store.setUserRole(userId, 'user');
            if(typeof store.logUserAction === 'function'){
              await store.logUserAction({
                userId,
                action: 'demoted-admin',
                reason: reason || null,
                detail: detail || null,
                actorId,
                actorType: 'admin',
              });
            }
            break;
          }
          case 'reset-password': {
            if(!userId) return sendJSON(res,400,{ error:'user-required' });
            if(!adminKeyValid){
              const superSession = await getSuperAdminSession();
              if(!superSession) return sendJSON(res,403,{ error:'superadmin-required', message:'슈퍼관리자만 사용할 수 있습니다.' });
            }
            if(typeof store.updateUserPassword !== 'function') return sendJSON(res,501,{ error:'password-unsupported' });
            const tempPassword = DEFAULT_TEMP_PASSWORD;
            const hash = sha256(tempPassword);
            await store.updateUserPassword(userId, hash);
            if(typeof store.invalidateUserSessions === 'function'){
              try{ await store.invalidateUserSessions(userId); }catch(err){ console.error('invalidate sessions failed', err); }
            }
            if(typeof store.logUserAction === 'function'){
              await store.logUserAction({
                userId,
                action: 'password-reset',
                reason: reason || null,
                detail: detail || '임시 비밀번호가 발급되었습니다.',
                actorId,
                actorType: 'admin',
              });
            }
            if(reportId) await resolveReport('closed');
            actionExtras = { tempPassword };
            break;
          }
          default:
            return sendJSON(res,400,{ error:'unsupported-action' });
        }
        return sendJSON(res,200,{ ok:true, ...actionExtras });
      }catch(err){
        const code = err?.code || 'admin-action-failed';
        const message = err?.message || '관리자 조치에 실패했습니다.';
        return sendJSON(res,400,{ error: code, message });
      }
    }

    if(pathname==='/api/announcements' && method==='GET'){
      if(typeof store.listAnnouncements !== 'function') return sendJSON(res,200,{ items: [] });
      const pinnedOnlyRaw = (u.searchParams.get('pinnedOnly') || u.searchParams.get('pinned') || '').toLowerCase();
      const pinnedOnly = pinnedOnlyRaw === 'true' || pinnedOnlyRaw === '1';
      const limitParam = Number(u.searchParams.get('limit') || '0');
      const limit = Number.isFinite(limitParam) && limitParam > 0 ? Math.floor(limitParam) : undefined;
      try{
        const items = await store.listAnnouncements({ pinnedOnly, limit });
        return sendJSON(res,200,{ items });
      }catch(err){
        console.error('announcement list error', err);
        if(err && err.code) return sendJSON(res,501,{ error: err.code, message: err.message });
        return sendJSON(res,500,{ error:'announcement-list-failed' });
      }
    }
    const publicAnnMatch = pathname.match(/^\/api\/announcements\/([^/]+)$/);
    if(publicAnnMatch && method==='GET'){
      if(typeof store.getAnnouncement !== 'function') return sendJSON(res,404,{ error:'not-found' });
      const annId = publicAnnMatch[1];
      try{
        const item = await store.getAnnouncement(annId);
        if(!item) return sendJSON(res,404,{ error:'not-found' });
        return sendJSON(res,200,{ item });
      }catch(err){
        console.error('announcement get error', err);
        if(err && err.code) return sendJSON(res,501,{ error: err.code, message: err.message });
        return sendJSON(res,500,{ error:'announcement-get-failed' });
      }
    }

    if(pathname==='/api/admin/announcements' && method==='GET'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      if(typeof store.listAnnouncements !== 'function') return sendJSON(res,501,{ error:'announcement-not-supported' });
      try{
        const items = await store.listAnnouncements({});
        return sendJSON(res,200,{ items });
      }catch(err){
        console.error('announcement admin list error', err);
        if(err && err.code) return sendJSON(res,501,{ error: err.code, message: err.message });
        return sendJSON(res,500,{ error:'announcement-list-failed' });
      }
    }
    if(pathname==='/api/admin/announcements' && method==='POST'){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      if(typeof store.createAnnouncement !== 'function') return sendJSON(res,501,{ error:'announcement-not-supported' });
      const body = await parseBody(req);
      const title = String(body.title || '').trim();
      const annBody = String(body.body || '').trim();
      if(!title || !annBody) return sendJSON(res,400,{ error:'validation', message:'title and body required' });
      try{
        const created = await store.createAnnouncement({ title, body: annBody, pinned: !!body.pinned });
        return sendJSON(res,200,{ ok:true, item: created });
      }catch(err){
        console.error('announcement create error', err);
        if(err && err.code) return sendJSON(res,501,{ error: err.code, message: err.message });
        return sendJSON(res,500,{ error:'announcement-create-failed' });
      }
    }
    const adminAnnMatch = pathname.match(/^\/api\/admin\/announcements\/([^/]+)$/);
    if(adminAnnMatch){
      if(!(await adminAllowed())) return sendJSON(res,403,{ error:'forbidden' });
      const annId = adminAnnMatch[1];
      if(method==='PATCH' || method==='PUT'){
        if(typeof store.updateAnnouncement !== 'function') return sendJSON(res,501,{ error:'announcement-not-supported' });
        const body = await parseBody(req);
        try{
          const updated = await store.updateAnnouncement(annId, {
            title: body.title,
            body: body.body,
            pinned: body.pinned,
          });
          if(!updated) return sendJSON(res,404,{ error:'not-found' });
          return sendJSON(res,200,{ ok:true, item: updated });
        }catch(err){
          console.error('announcement update error', err);
          if(err && err.code) return sendJSON(res,501,{ error: err.code, message: err.message });
          return sendJSON(res,500,{ error:'announcement-update-failed' });
        }
      }
      if(method==='DELETE'){
        if(typeof store.deleteAnnouncement !== 'function') return sendJSON(res,501,{ error:'announcement-not-supported' });
        try{
          const ok = await store.deleteAnnouncement(annId);
          if(!ok) return sendJSON(res,404,{ error:'not-found' });
          return sendJSON(res,200,{ ok:true });
        }catch(err){
          console.error('announcement delete error', err);
          if(err && err.code) return sendJSON(res,501,{ error: err.code, message: err.message });
          return sendJSON(res,500,{ error:'announcement-delete-failed' });
        }
      }
    }

    if(pathname==='/api/handles/check' && method==='GET'){
      const handleParam = (u.searchParams.get('handle') || '').trim();
      const normalized = normalizeHandle(handleParam);
      let available = false;
      if(normalized){
        const existing = await store.findUserByHandle(normalized);
        available = !existing;
      }
      return sendJSON(res,200,{ formatValid: !!normalized, available: !!normalized && available });
    }
    if(pathname==='/api/signup' && method==='POST'){
      const body = await parseBody(req);
      const email = normalizeEmail(body.email);
      const phone = normalizePhone(body.phone);
      const handle = normalizeHandle(body.handle);
      const name = String(body.name || '').trim();
      const password = String(body.password || '');
      if(!email) return sendJSON(res,400,{ error:'email-invalid' });
      if(!phone) return sendJSON(res,400,{ error:'phone-invalid' });
      if(!handle) return sendJSON(res,400,{ error:'handle-invalid' });
      if(!name) return sendJSON(res,400,{ error:'name-required' });
      if(!validatePasswordStrength(password)) return sendJSON(res,400,{ error:'password-weak' });

      const [emailUser, phoneUser, handleUser] = await Promise.all([
        store.findUserByEmail && store.findUserByEmail(email),
        store.findUserByPhone && store.findUserByPhone(phone),
        store.findUserByHandle(handle),
      ]);
      if(emailUser) return sendJSON(res,409,{ error:'email-taken' });
      if(phoneUser) return sendJSON(res,409,{ error:'phone-taken' });
      if(handleUser) return sendJSON(res,409,{ error:'handle-taken' });

      const config = typeof store.getConfig === 'function' ? await store.getConfig() : { requiresReferralCode:false };
      const referralCodeRaw = String(body.referralCode || body.inviteCode || '').trim().toUpperCase();
      const requiresReferral = !!config?.requiresReferralCode;
      if(requiresReferral){
        if(!referralCodeRaw) return sendJSON(res,400,{ error:'referral-required' });
        if(typeof store.verifyReferralCode !== 'function') return sendJSON(res,501,{ error:'referral-not-supported' });
        try{
          const check = await store.verifyReferralCode(referralCodeRaw);
          if(!check?.valid){
            return sendJSON(res,400,{ error:'referral-invalid', reason: check?.reason || null });
          }
        }catch(err){
          console.error('referral verify during signup error', err);
          if(err && err.code) return sendJSON(res,501,{ error: err.code, message: err.message });
          return sendJSON(res,500,{ error:'referral-verify-failed' });
        }
      }else if(referralCodeRaw && typeof store.verifyReferralCode === 'function'){
        try{
          const check = await store.verifyReferralCode(referralCodeRaw);
          if(!check?.valid){
            return sendJSON(res,400,{ error:'referral-invalid', reason: check?.reason || null });
          }
        }catch(err){
          console.error('referral optional verify error', err);
        }
      }

      let avatarUrl = null;
      if(body.avatar && body.avatar.data){
        try{
          const stored = await saveBinaryToStorage({
            folder: 'avatars',
            filename: body.avatar.filename || 'avatar',
            base64: body.avatar.data,
            contentType: body.avatar.contentType || 'application/octet-stream',
          });
          avatarUrl = stored?.url || null;
        }catch(err){
          if(err && err.code === 'file-too-large') return sendJSON(res,413,{ error:'avatar-too-large' });
          return sendJSON(res,400,{ error:'avatar-invalid' });
        }
      }

      const passwordHash = sha256(password);
      const userRecord = await store.createUser({ email, phone, passwordHash, handle, name, avatarUrl });
      if(referralCodeRaw && typeof store.consumeReferralCode === 'function'){
        try{
          await store.consumeReferralCode(referralCodeRaw, { userId: userRecord.id });
        }catch(err){
          console.error('referral consume error', err);
        }
      }
      const sid = await store.createSession(userRecord.id);
      setCookie(res,'sid',sid,{ path:'/', httpOnly:true, sameSite:'Lax', maxAge:60*60*24*30 });
      const presentedUser = store.publicUser ? store.publicUser(userRecord) : userRecord;
      return sendJSON(res,200,{ ok:true, user: withSuperAdminMeta(presentedUser) });
    }

    // Session
    if(pathname==='/api/session' && method==='GET'){
      const sid = cookies['sid'];
      const user = await store.getSessionUser(sid);
      return sendJSON(res,200,{ user: withSuperAdminMeta(user) });
    }
    if(pathname==='/api/login' && method==='POST'){
      const body = await parseBody(req);
      const identifierRaw = body.identifier || body.handle || body.email || '';
      const password = String(body.password || '');
      if(!identifierRaw || !password) return sendJSON(res,400,{ error:'missing-credentials' });
      const identifier = String(identifierRaw).trim();
      let user = null;
      const handleCandidate = normalizeHandle(identifier);
      if(handleCandidate) user = await store.findUserByHandle(handleCandidate);
      if(!user){
        const emailCandidate = normalizeEmail(identifier);
        if(emailCandidate && store.findUserByEmail){
          user = await store.findUserByEmail(emailCandidate);
        }
      }
      if(!user && !identifier.includes('@')){
        const fallbackHandle = normalizeHandle(`@${identifier}`);
        if(fallbackHandle) user = await store.findUserByHandle(fallbackHandle);
      }
      if(!user) return sendJSON(res,401,{ error:'invalid' });
      async function buildAccountStatus(code, targetUser){
        const payload = {
          error: code,
          status: targetUser.status || null,
          suspendedUntil: targetUser.suspendedUntil || null,
        };
        if(typeof store.getLatestAccountAction === 'function'){
          try{
            const action = await store.getLatestAccountAction(targetUser.id);
            if(action){
              payload.reason = action.reason || null;
              payload.detail = action.detail || null;
              payload.action = action.action || null;
              payload.recordedAt = action.createdAt || null;
              payload.actor = action.actor || null;
            }
          }catch(err){
            console.error('latest account action fetch error', err);
          }
        }
        return payload;
      }
      if(user.status && user.status !== 'active'){
        const code = user.status === 'deleted'
          ? 'account-deleted'
          : user.status === 'suspended'
          ? 'account-suspended'
          : 'account-deactivated';
        return sendJSON(res,403,await buildAccountStatus(code, user));
      }
      if(user.passwordHash !== sha256(password)) return sendJSON(res,401,{ error:'invalid' });
      let sid;
      try{
        sid = await store.createSession(user.id);
      }catch(err){
        if(err && (err.code === 'account-deleted' || err.code === 'account-deactivated' || err.code === 'account-suspended')){
          const code = err.code;
          return sendJSON(res,403,await buildAccountStatus(code, user));
        }
        throw err;
      }
      setCookie(res,'sid',sid,{ path:'/', httpOnly:true, sameSite:'Lax', maxAge:60*60*24*30 });
      const presentedUser = store.publicUser ? store.publicUser(user) : user;
      return sendJSON(res,200,{ ok:true, user: withSuperAdminMeta(presentedUser) });
    }
    if(pathname==='/api/logout' && method==='POST'){
      const sid = cookies['sid'];
      await store.deleteSession(sid);
      setCookie(res,'sid','',{ path:'/', httpOnly:true, sameSite:'Lax', maxAge:0 });
      return sendJSON(res,200,{ ok:true });
    }
    if(pathname==='/api/profile' && method==='GET'){
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      if(typeof store.getUserProfile !== 'function') return sendJSON(res,501,{ error:'profile-unsupported' });
      try{
        const profile = await store.getUserProfile(sessionUser.id);
        return sendJSON(res,200,{ user: profile || sessionUser });
      }catch(err){
        console.error('profile get error', err);
        return sendJSON(res,500,{ error:'profile-error' });
      }
    }
    if(pathname==='/api/profile' && method==='PUT'){
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      if(typeof store.updateUserProfile !== 'function') return sendJSON(res,501,{ error:'profile-unsupported' });
      const body = await parseBody(req);
      const name = String(body.name || '').trim();
      if(!name) return sendJSON(res,400,{ error:'name-required', message:'이름을 입력해 주세요.' });
      const updates = { name };

      if(body.handle !== undefined){
        const normalizedHandle = normalizeHandle(body.handle);
        if(!normalizedHandle) return sendJSON(res,400,{ error:'handle-invalid' });
        if(normalizedHandle !== sessionUser.handle){
          const existingHandle = await store.findUserByHandle(normalizedHandle);
          if(existingHandle && existingHandle.id !== sessionUser.id){
            return sendJSON(res,409,{ error:'handle-taken' });
          }
        }
        updates.handle = normalizedHandle;
      }

      if(body.email !== undefined){
        const normalizedEmail = normalizeEmail(body.email);
        if(!normalizedEmail) return sendJSON(res,400,{ error:'email-invalid' });
        if(normalizedEmail !== sessionUser.email && store.findUserByEmail){
          const existingEmail = await store.findUserByEmail(normalizedEmail);
          if(existingEmail && existingEmail.id !== sessionUser.id){
            return sendJSON(res,409,{ error:'email-taken' });
          }
        }
        updates.email = normalizedEmail;
      }

      if(body.phone !== undefined){
        const normalizedPhone = normalizePhone(body.phone);
        if(!normalizedPhone) return sendJSON(res,400,{ error:'phone-invalid' });
        if(normalizedPhone !== sessionUser.phone && store.findUserByPhone){
          const existingPhone = await store.findUserByPhone(normalizedPhone);
          if(existingPhone && existingPhone.id !== sessionUser.id){
            return sendJSON(res,409,{ error:'phone-taken' });
          }
        }
        updates.phone = normalizedPhone;
      }

      if(body.avatar && body.avatar.data){
        try{
          const stored = await saveBinaryToStorage({
            folder: 'avatars',
            filename: body.avatar.filename || 'avatar',
            base64: body.avatar.data,
            contentType: body.avatar.contentType || 'application/octet-stream',
          });
          updates.avatarUrl = stored?.url || null;
        }catch(err){
          if(err && err.code === 'file-too-large') return sendJSON(res,413,{ error:'avatar-too-large' });
          return sendJSON(res,400,{ error:'avatar-invalid' });
        }
      }else if(body.removeAvatar){
        updates.avatarUrl = null;
      }

      try{
        const updated = await store.updateUserProfile(sessionUser.id, updates);
        return sendJSON(res,200,{ ok:true, user: updated });
      }catch(err){
        if(err && err.code){
          if(err.code === 'invalid-name') return sendJSON(res,400,{ error:'name-invalid', message: err.message });
        }
        console.error('profile update error', err);
        return sendJSON(res,500,{ error:'profile-error' });
      }
    }
    if(pathname==='/api/users/profile' && method==='GET'){
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      const handleParamRaw = (u.searchParams.get('handle') || '').trim();
      const normalizedHandleParam = handleParamRaw ? normalizeHandle(handleParamRaw) : null;
      if (handleParamRaw && !normalizedHandleParam) return sendJSON(res,400,{ error:'handle-invalid' });
      const idParam = (u.searchParams.get('id') || '').trim() || null;
      const limitParam = u.searchParams.get('limit');
      const limit = limitParam ? Math.max(0, Math.min(parseInt(limitParam, 10) || 0, 50)) : 20;
      if (!normalizedHandleParam && !idParam && !sessionUser) {
        return sendJSON(res,401,{ error:'auth-required' });
      }
      const handleParam = normalizedHandleParam || null;
      const effectiveUserId = idParam || (!handleParam && sessionUser ? sessionUser.id : null);
      try{
        const profileData = typeof store.getUserProfileView === 'function'
          ? await store.getUserProfileView({
            handle: handleParam,
            userId: effectiveUserId,
            viewerId: sessionUser?.id || null,
            limit,
          })
          : null;
        if(!profileData || !profileData.user){
          if(sessionUser && (!handleParam || handleParam === sessionUser.handle)){
            let fallbackData = null;
            if (typeof store.getUserProfileView === 'function') {
              try {
                fallbackData = await store.getUserProfileView({
                  userId: sessionUser.id,
                  viewerId: sessionUser.id,
                  limit,
                });
              } catch (err) {
                const mapped = mapMessageError(err);
                if (mapped.status >= 500) console.error('profile fallback error', err);
              }
            }
            if (!fallbackData || !fallbackData.user) {
              fallbackData = {
                user: sessionUser,
                stats: { followers: 0, following: 0, posts: 0 },
                posts: [],
                isFollowing: false,
              };
            }
            return sendJSON(res,200,{
              user: fallbackData.user,
              stats: fallbackData.stats || { followers:0, following:0, posts:0 },
              posts: Array.isArray(fallbackData.posts) ? fallbackData.posts : [],
              isFollowing: !!fallbackData.isFollowing,
              isSelf: true,
              viewer: sessionUser,
            });
          }
          return sendJSON(res,404,{ error:'user-not-found' });
        }
        const isSelf = !!(sessionUser && profileData.user && sessionUser.id === profileData.user.id);
        return sendJSON(res,200,{
          user: profileData.user,
          stats: profileData.stats || { followers:0, following:0, posts:0 },
          posts: profileData.posts || [],
          isFollowing: !!profileData.isFollowing,
          isSelf,
          viewer: profileData.viewer || sessionUser || null,
        });
      }catch(err){
        const mapped = mapMessageError(err);
        return sendJSON(res,mapped.status,mapped.payload);
      }
    }

    if(pathname==='/api/explore/summary' && method==='GET'){
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      const trendingRaw = u.searchParams.get('trendingLimit') ?? u.searchParams.get('trending_limit');
      const suggestionsRaw = u.searchParams.get('suggestionLimit') ?? u.searchParams.get('suggestion_limit');
      const trendingParsed = trendingRaw != null ? parseInt(trendingRaw, 10) : NaN;
      const suggestionsParsed = suggestionsRaw != null ? parseInt(suggestionsRaw, 10) : NaN;
      const trendingLimit = Number.isFinite(trendingParsed) ? Math.max(0, Math.min(trendingParsed, 20)) : 6;
      const suggestionLimit = Number.isFinite(suggestionsParsed) ? Math.max(0, Math.min(suggestionsParsed, 20)) : 6;
      let trending = [];
      let suggestedUsers = [];
      if (typeof store.getTrendingTags === 'function') {
        try{
          trending = await store.getTrendingTags({ limit: trendingLimit });
        }catch(err){
          console.error('explore trending error', err);
        }
      }
      if (typeof store.listRandomUsers === 'function') {
        try{
          suggestedUsers = await store.listRandomUsers({
            viewerId: sessionUser?.id || null,
            excludeIds: sessionUser ? [sessionUser.id] : [],
            limit: suggestionLimit,
          });
        }catch(err){
          console.error('explore suggestions error', err);
        }
      }
      return sendJSON(res,200,{
        viewer: sessionUser || null,
        trending: Array.isArray(trending) ? trending : [],
        suggestedUsers: Array.isArray(suggestedUsers) ? suggestedUsers : [],
      });
    }

    if(pathname==='/api/search' && method==='GET'){
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      const queryRaw = (u.searchParams.get('q') || '').trim();
      if(!queryRaw) return sendJSON(res,400,{ error:'query-required' });
      const scopeParam = (u.searchParams.get('scope') || 'all').trim().toLowerCase();
      const scope = ['all','users','posts','tags'].includes(scopeParam) ? scopeParam : 'all';
      const parseLimit = (names, fallback, max) => {
        const rawVal = names.map((name) => u.searchParams.get(name)).find((val)=> val != null);
        const parsed = rawVal != null ? parseInt(rawVal, 10) : NaN;
        if(!Number.isFinite(parsed)) return fallback;
        return Math.max(1, Math.min(parsed, max));
      };
      const userLimit = parseLimit(['userLimit','user_limit'], scope === 'users' ? 20 : 10, 50);
      const postLimit = parseLimit(['postLimit','post_limit'], scope === 'posts' ? 20 : 12, 50);
      const tagLimit = parseLimit(['tagLimit','tag_limit'], 10, 50);
      let tagQuery = null;
      if(queryRaw.startsWith('#')){
        const trimmed = queryRaw.slice(1).trim().toLowerCase();
        if(trimmed) tagQuery = trimmed;
      }
      const viewerId = sessionUser?.id || null;
      const response = {
        query: queryRaw,
        scope,
        users: [],
        posts: [],
        tags: [],
        viewer: sessionUser || null,
      };
      if((scope==='all' || scope==='users') && typeof store.searchUsers === 'function'){
        try{
          const users = await store.searchUsers({
            query: queryRaw,
            viewerId,
            excludeIds: [],
            limit: userLimit,
          });
          response.users = Array.isArray(users) ? users : [];
        }catch(err){
          console.error('search users error', err);
        }
      }
      if((scope==='all' || scope==='posts') && typeof store.searchPosts === 'function'){
        try{
          const posts = await store.searchPosts({
            query: queryRaw,
            tag: tagQuery,
            limit: postLimit,
          });
          response.posts = Array.isArray(posts) ? posts : [];
        }catch(err){
          console.error('search posts error', err);
        }
      }
      if((scope==='all' || scope==='tags') && typeof store.searchTags === 'function'){
        try{
          const tags = await store.searchTags({
            query: queryRaw,
            limit: tagLimit,
          });
          response.tags = Array.isArray(tags) ? tags : [];
        }catch(err){
          console.error('search tags error', err);
        }
      }
      return sendJSON(res,200,response);
    }

    if(pathname==='/api/account/password' && method==='PUT'){
      if(typeof store.updateUserPassword !== 'function') return sendJSON(res,501,{ error:'password-unsupported' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      const body = await parseBody(req);
      const currentPassword = String(body.currentPassword || '');
      const newPassword = String(body.newPassword || '');
      if(!currentPassword || !newPassword) return sendJSON(res,400,{ error:'missing-fields' });
      if(!validatePasswordStrength(newPassword)) return sendJSON(res,400,{ error:'password-weak' });
      try{
        const authInfo = typeof store.getUserAuth === 'function'
          ? await store.getUserAuth(sessionUser.id)
          : null;
        if(!authInfo || !authInfo.passwordHash) return sendJSON(res,500,{ error:'password-unavailable' });
        const currentHash = sha256(currentPassword);
        if(authInfo.passwordHash !== currentHash) return sendJSON(res,400,{ error:'password-mismatch' });
        const newHash = sha256(newPassword);
        if(newHash === authInfo.passwordHash) return sendJSON(res,400,{ error:'password-same' });
        await store.updateUserPassword(sessionUser.id, newHash);
        if(typeof store.invalidateUserSessions === 'function'){
          await store.invalidateUserSessions(sessionUser.id);
        }
        if(typeof store.createSession === 'function'){
          try{
            const newSid = await store.createSession(sessionUser.id);
            if(typeof store.deleteSession === 'function') await store.deleteSession(sid);
            setCookie(res,'sid',newSid,{ path:'/', httpOnly:true, sameSite:'Lax', maxAge:60*60*24*30 });
          }catch(err){
            if(err && err.code === 'account-deleted') return sendJSON(res,403,{ error:'account-deleted' });
            if(err && err.code === 'account-deactivated') return sendJSON(res,403,{ error:'account-deactivated' });
            throw err;
          }
        }
        return sendJSON(res,200,{ ok:true });
      }catch(err){
        console.error('password update error', err);
        if(err && err.code === 'auth-required') return sendJSON(res,401,{ error:'auth-required' });
        return sendJSON(res,500,{ error:'password-error' });
      }
    }

    if(pathname==='/api/account/actions' && method==='GET'){
      if(typeof store.listAccountActions !== 'function') return sendJSON(res,501,{ error:'account-unsupported' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      try{
        const actions = await store.listAccountActions(sessionUser.id);
        return sendJSON(res,200,{ actions: Array.isArray(actions) ? actions : [] });
      }catch(err){
        if(err && err.code === 'account-disabled') return sendJSON(res,501,{ error:'account-disabled', message: err.message });
        if(err && err.code === 'auth-required') return sendJSON(res,401,{ error:'auth-required' });
        console.error('account actions error', err);
        return sendJSON(res,500,{ error:'account-actions-error' });
      }
    }

    if(pathname==='/api/account/deactivate' && method==='POST'){
      if(typeof store.deactivateAccount !== 'function') return sendJSON(res,501,{ error:'account-unsupported' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      const body = await parseBody(req);
      const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
      try{
        await store.deactivateAccount(sessionUser.id, {
          reason,
          actorId: sessionUser.id,
          actorType: 'self',
        });
        if(typeof store.deleteSession === 'function') await store.deleteSession(sid);
        if(typeof store.invalidateUserSessions === 'function') await store.invalidateUserSessions(sessionUser.id);
        setCookie(res,'sid','',{ path:'/', httpOnly:true, sameSite:'Lax', maxAge:0 });
        return sendJSON(res,200,{ ok:true });
      }catch(err){
        if(err && err.code === 'account-disabled') return sendJSON(res,501,{ error:'account-disabled', message: err.message });
        if(err && err.code === 'account-deleted') return sendJSON(res,400,{ error:'account-deleted' });
        if(err && err.code === 'account-already-deactivated') return sendJSON(res,400,{ error:'account-already-deactivated' });
        if(err && err.code === 'account-suspended') return sendJSON(res,400,{ error:'account-suspended' });
        if(err && err.code === 'auth-required') return sendJSON(res,401,{ error:'auth-required' });
        console.error('account deactivate error', err);
        return sendJSON(res,500,{ error:'account-deactivate-error' });
      }
    }

    if(pathname==='/api/account' && method==='DELETE'){
      if(typeof store.deleteAccount !== 'function') return sendJSON(res,501,{ error:'account-unsupported' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      const body = await parseBody(req);
      const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
      const detail = typeof body.detail === 'string' ? body.detail.trim() : '';
      const confirmation = typeof body.confirm === 'string' ? body.confirm.trim() : '';
      const expected = sessionUser.handle || '';
      if(!expected || confirmation !== expected){
        return sendJSON(res,400,{ error:'confirm-mismatch', message:'확인용 아이디가 일치하지 않습니다.' });
      }
      try{
        await store.deleteAccount(sessionUser.id, {
          reason,
          detail,
          actorId: sessionUser.id,
          actorType: 'self',
        });
        if(typeof store.deleteSession === 'function') await store.deleteSession(sid);
        if(typeof store.invalidateUserSessions === 'function') await store.invalidateUserSessions(sessionUser.id);
        setCookie(res,'sid','',{ path:'/', httpOnly:true, sameSite:'Lax', maxAge:0 });
        return sendJSON(res,200,{ ok:true });
      }catch(err){
        if(err && err.code === 'account-disabled') return sendJSON(res,501,{ error:'account-disabled', message: err.message });
        if(err && err.code === 'account-deleted') return sendJSON(res,400,{ error:'account-deleted' });
        if(err && err.code === 'account-suspended') return sendJSON(res,400,{ error:'account-suspended' });
        if(err && err.code === 'auth-required') return sendJSON(res,401,{ error:'auth-required' });
        console.error('account delete error', err);
        return sendJSON(res,500,{ error:'account-delete-error' });
      }
    }

    if(pathname==='/api/notifications' && method==='GET'){
      if(typeof store.listNotifications !== 'function') return sendJSON(res,501,{ error:'notifications-unsupported' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      const typeRaw = (u.searchParams.get('type') || 'all').trim().toLowerCase();
      const allowedTypes = new Set(['all','comment','follow']);
      const type = allowedTypes.has(typeRaw) ? typeRaw : 'all';
      const limitParam = Number(u.searchParams.get('limit') || '20');
      const limit = Number.isFinite(limitParam) ? limitParam : 20;
      try{
        const notifications = await store.listNotifications(sessionUser.id, { type, limit, markSeen:true });
        return sendJSON(res,200,{ notifications: Array.isArray(notifications) ? notifications : [] });
      }catch(err){
        if(err && err.code === 'notifications-disabled') return sendJSON(res,501,{ error:'notifications-disabled', message: err.message });
        console.error('notifications list error', err);
        return sendJSON(res,500,{ error:'notifications-error' });
      }
    }

    if(pathname==='/api/notifications/count' && method==='GET'){
      if(typeof store.countUnreadNotifications !== 'function') return sendJSON(res,501,{ error:'notifications-unsupported' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,200,{ count:0 });
      try{
        const count = await store.countUnreadNotifications(sessionUser.id);
        return sendJSON(res,200,{ count: Number(count) || 0 });
      }catch(err){
        if(err && err.code === 'notifications-disabled') return sendJSON(res,501,{ error:'notifications-disabled', message: err.message });
        console.error('notifications count error', err);
        return sendJSON(res,500,{ error:'notifications-error' });
      }
    }

    if(pathname==='/api/admin/accounts/suspend' && method==='POST'){
      if(typeof store.suspendAccount !== 'function') return sendJSON(res,501,{ error:'account-unsupported' });
      const key = req.headers['x-admin-key'];
      if(key!==ADMIN_KEY) return sendJSON(res,403,{ error:'forbidden' });
      const body = await parseBody(req);
      const target = await resolveUserForAdminTarget(body || {});
      if(!target || !target.id) return sendJSON(res,404,{ error:'user-not-found' });
      const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
      const detail = typeof body.detail === 'string' ? body.detail.trim() : '';
      let until = null;
      if(body.until){
        const parsed = new Date(body.until);
        if(Number.isFinite(parsed.getTime())){
          until = parsed.toISOString();
        }else{
          return sendJSON(res,400,{ error:'invalid-until', message:'정지 종료일이 유효하지 않습니다.' });
        }
      }
      try{
        const result = await store.suspendAccount(target.id, {
          reason,
          detail,
          until,
          actorId: typeof body.actorId === 'string' ? body.actorId : null,
          actorType: 'admin',
        });
        return sendJSON(res,200,{ ok:true, user: result || null });
      }catch(err){
        if(err && err.code === 'account-disabled') return sendJSON(res,501,{ error:'account-disabled', message: err.message });
        if(err && err.code === 'account-deleted') return sendJSON(res,400,{ error:'account-deleted' });
        if(err && err.code === 'account-already-suspended') return sendJSON(res,400,{ error:'account-already-suspended' });
        if(err && err.code === 'auth-required') return sendJSON(res,401,{ error:'auth-required' });
        if(err && err.code === 'account-active') return sendJSON(res,409,{ error:'account-active' });
        console.error('admin suspend error', err);
        return sendJSON(res,500,{ error:'account-suspend-error' });
      }
    }

    if(pathname==='/api/admin/accounts/restore' && method==='POST'){
      if(typeof store.restoreAccount !== 'function') return sendJSON(res,501,{ error:'account-unsupported' });
      const key = req.headers['x-admin-key'];
      if(key!==ADMIN_KEY) return sendJSON(res,403,{ error:'forbidden' });
      const body = await parseBody(req);
      const target = await resolveUserForAdminTarget(body || {});
      if(!target || !target.id) return sendJSON(res,404,{ error:'user-not-found' });
      const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
      const detail = typeof body.detail === 'string' ? body.detail.trim() : '';
      try{
        const result = await store.restoreAccount(target.id, {
          reason,
          detail,
          actorId: typeof body.actorId === 'string' ? body.actorId : null,
          actorType: 'admin',
        });
        return sendJSON(res,200,{ ok:true, user: result || null });
      }catch(err){
        if(err && err.code === 'account-disabled') return sendJSON(res,501,{ error:'account-disabled', message: err.message });
        if(err && err.code === 'account-deleted') return sendJSON(res,400,{ error:'account-deleted' });
        if(err && err.code === 'auth-required') return sendJSON(res,401,{ error:'auth-required' });
        if(err && err.code === 'account-active') return sendJSON(res,409,{ error:'account-active' });
        console.error('admin restore error', err);
        return sendJSON(res,500,{ error:'account-restore-error' });
      }
    }

    if(pathname==='/api/users/followers' && method==='GET'){
      if(typeof store.listFollowers !== 'function') return sendJSON(res,501,{ error:'profile-unsupported' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      const handleParamRaw = (u.searchParams.get('handle') || '').trim();
      const idParamRaw = (u.searchParams.get('id') || '').trim();
      const limitParam = u.searchParams.get('limit');
      const limit = limitParam ? Math.max(0, Math.min(parseInt(limitParam, 10) || 0, 100)) : 50;
      let targetUser = null;
      let targetId = idParamRaw || null;
      if(handleParamRaw){
        const normalizedHandle = normalizeHandle(handleParamRaw);
        if(!normalizedHandle) return sendJSON(res,400,{ error:'handle-invalid' });
        const fetchedByHandle = await store.findUserByHandle?.(normalizedHandle);
        if(!fetchedByHandle) return sendJSON(res,404,{ error:'user-not-found' });
        targetUser = fetchedByHandle;
        targetId = fetchedByHandle.id;
      }
      if(!targetId && sessionUser){
        targetUser = sessionUser;
        targetId = sessionUser.id;
      }
      if(!targetId) return sendJSON(res,400,{ error:'target-required' });
      if(!targetUser && typeof store.getUserProfile === 'function'){
        try{
          targetUser = await store.getUserProfile(targetId);
        }catch{/* ignore */}
      }
      if(!targetUser){
        if(sessionUser && sessionUser.id === targetId) targetUser = sessionUser;
      }
      if(!targetUser) return sendJSON(res,404,{ error:'user-not-found' });
      try{
        const entries = await store.listFollowers(targetId, {
          viewerId: sessionUser?.id || null,
          limit,
        });
        return sendJSON(res,200,{
          target: store.publicUser ? store.publicUser(targetUser) : targetUser,
          users: (entries || []).map((entry)=>({
            user: entry?.user || null,
            followedAt: entry?.followedAt || null,
            isFollowing: !!entry?.isFollowing,
            isMutual: !!entry?.isMutual,
          })),
          viewer: sessionUser || null,
          isSelf: !!(sessionUser && targetId === sessionUser.id),
        });
      }catch(err){
        const mapped = mapMessageError(err);
        return sendJSON(res,mapped.status,mapped.payload);
      }
    }

    if(pathname==='/api/users/following' && method==='GET'){
      if(typeof store.listFollowing !== 'function') return sendJSON(res,501,{ error:'profile-unsupported' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      const handleParamRaw = (u.searchParams.get('handle') || '').trim();
      const idParamRaw = (u.searchParams.get('id') || '').trim();
      const limitParam = u.searchParams.get('limit');
      const limit = limitParam ? Math.max(0, Math.min(parseInt(limitParam, 10) || 0, 100)) : 50;
      let targetUser = null;
      let targetId = idParamRaw || null;
      if(handleParamRaw){
        const normalizedHandle = normalizeHandle(handleParamRaw);
        if(!normalizedHandle) return sendJSON(res,400,{ error:'handle-invalid' });
        const fetchedByHandle = await store.findUserByHandle?.(normalizedHandle);
        if(!fetchedByHandle) return sendJSON(res,404,{ error:'user-not-found' });
        targetUser = fetchedByHandle;
        targetId = fetchedByHandle.id;
      }
      if(!targetId && sessionUser){
        targetUser = sessionUser;
        targetId = sessionUser.id;
      }
      if(!targetId) return sendJSON(res,400,{ error:'target-required' });
      if(!targetUser && typeof store.getUserProfile === 'function'){
        try{
          targetUser = await store.getUserProfile(targetId);
        }catch{/* ignore */}
      }
      if(!targetUser){
        if(sessionUser && sessionUser.id === targetId) targetUser = sessionUser;
      }
      if(!targetUser) return sendJSON(res,404,{ error:'user-not-found' });
      try{
        const entries = await store.listFollowing(targetId, {
          viewerId: sessionUser?.id || null,
          limit,
        });
        return sendJSON(res,200,{
          target: store.publicUser ? store.publicUser(targetUser) : targetUser,
          users: (entries || []).map((entry)=>({
            user: entry?.user || null,
            followedAt: entry?.followedAt || null,
            isFollowing: !!entry?.isFollowing,
            isMutual: !!entry?.isMutual,
          })),
          viewer: sessionUser || null,
          isSelf: !!(sessionUser && targetId === sessionUser.id),
        });
      }catch(err){
        const mapped = mapMessageError(err);
        return sendJSON(res,mapped.status,mapped.payload);
      }
    }

    if(pathname==='/api/messages/channels' && method==='POST'){
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      if(await enforceChatAvailability(sessionUser)) return;
      const body = await parseBody(req);
      if(body?.type && body.type !== 'group') return sendJSON(res,400,{ error:'unsupported-type' });
      try{
        const channel = await store.createMessageGroup({
          userId: sessionUser.id,
          name: body?.name,
          desc: body?.desc,
          tags: body?.tags,
        });
        return sendJSON(res,200,{ channel });
      }catch(err){
        const mapped = mapMessageError(err);
        return sendJSON(res,mapped.status,mapped.payload);
      }
    }
    const followMatch = pathname.match(/^\/api\/users\/([^/]+)\/follow$/);
    if(followMatch && (method==='POST' || method==='DELETE')){
      const targetRaw = decodeURIComponent(followMatch[1]);
      const normalizedHandle = normalizeHandle(targetRaw);
      if(!normalizedHandle) return sendJSON(res,400,{ error:'handle-invalid' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      const targetUser = await store.findUserByHandle(normalizedHandle);
      if(!targetUser) return sendJSON(res,404,{ error:'user-not-found' });
      if(targetUser.id === sessionUser.id) return sendJSON(res,400,{ error:'invalid-target' });
      try{
        const profileData = method === 'POST'
          ? await store.followUser(sessionUser.id, targetUser.id)
          : await store.unfollowUser(sessionUser.id, targetUser.id);
        const stats = profileData?.stats || null;
        return sendJSON(res,200,{
          ok:true,
          following: method === 'POST',
          stats,
        });
      }catch(err){
        const mapped = mapMessageError(err);
        return sendJSON(res,mapped.status,mapped.payload);
      }
    }
    if(pathname==='/api/messages/channels' && method==='GET'){
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      if(await isChatRestrictedFor(sessionUser)){
        return sendJSON(res,200,{ user: sessionUser, channels: [], groups: [], chatRestricted: true });
      }
      try{
        const result = await store.listMessageChannels(sessionUser.id);
        return sendJSON(res,200,{
          user: sessionUser,
          channels: result?.channels || [],
          groups: result?.groups || [],
          chatRestricted: false,
        });
      }catch(err){
        const mapped = mapMessageError(err);
        return sendJSON(res,mapped.status,mapped.payload);
      }
    }
    if(pathname==='/api/messages/direct' && method==='POST'){
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
       if(await enforceChatAvailability(sessionUser)) return;
      const body = await parseBody(req);
      const handleRaw = body?.handle || body?.target || '';
      const normalizedHandle = normalizeHandle(handleRaw);
      if(!normalizedHandle) return sendJSON(res,400,{ error:'handle-invalid' });
      const targetUser = await store.findUserByHandle(normalizedHandle);
      if(!targetUser) return sendJSON(res,404,{ error:'user-not-found' });
      if(targetUser.id === sessionUser.id) return sendJSON(res,400,{ error:'invalid-target' });
      try{
        const channel = await store.ensureDirectChannel({ viewerId: sessionUser.id, targetId: targetUser.id });
        return sendJSON(res,200,{ channel });
      }catch(err){
        const mapped = mapMessageError(err);
        return sendJSON(res,mapped.status,mapped.payload);
      }
    }
    const joinChannelMatch = pathname.match(/^\/api\/messages\/channels\/([^/]+)\/join$/);
    if(joinChannelMatch && method==='POST'){
      const channelId = decodeURIComponent(joinChannelMatch[1]);
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      if(await enforceChatAvailability(sessionUser)) return;
      try{
        const channel = await store.joinMessageChannel(channelId, sessionUser.id);
        return sendJSON(res,200,{ channel });
      }catch(err){
        const mapped = mapMessageError(err);
        return sendJSON(res,mapped.status,mapped.payload);
      }
    }
    const leaveChannelMatch = pathname.match(/^\/api\/messages\/channels\/([^/]+)\/leave$/);
    if(leaveChannelMatch && method==='POST'){
      const channelId = decodeURIComponent(leaveChannelMatch[1]);
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      if(await enforceChatAvailability(sessionUser)) return;
      try{
        await store.leaveMessageChannel(channelId, sessionUser.id);
        return sendJSON(res,200,{ ok:true, channelId });
      }catch(err){
        const mapped = mapMessageError(err);
        return sendJSON(res,mapped.status,mapped.payload);
      }
    }
    const channelMessagesMatch = pathname.match(/^\/api\/messages\/channels\/([^/]+)\/messages$/);
    if(channelMessagesMatch){
      const channelId = decodeURIComponent(channelMessagesMatch[1]);
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'auth-required' });
      if(method==='GET'){
        const limitParam = u.searchParams.get('limit');
        const limit = limitParam ? parseInt(limitParam,10) : undefined;
        const afterRaw = u.searchParams.get('after') || u.searchParams.get('since');
        let afterIso = null;
        if(afterRaw){
          const parsed = new Date(afterRaw);
          if(Number.isFinite(parsed.getTime())) afterIso = parsed.toISOString();
        }
        try{
          const opts = { userId: sessionUser.id, limit };
          if(afterIso) opts.after = afterIso;
          const data = await store.listChannelMessages(channelId, opts);
          return sendJSON(res,200,data);
        }catch(err){
          const mapped = mapMessageError(err);
          return sendJSON(res,mapped.status,mapped.payload);
        }
      }
      if(method==='POST'){
        const body = await parseBody(req);
        try{
          const message = await store.appendChannelMessage(channelId, { user: sessionUser, text: body?.text || body?.message });
          return sendJSON(res,200,{ message });
        }catch(err){
          const mapped = mapMessageError(err);
          return sendJSON(res,mapped.status,mapped.payload);
        }
      }
    }

    // Posts
    if(pathname==='/api/posts' && method==='GET'){
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      const postsRaw = await store.listPosts();
      const posts = presentPostsForClient(postsRaw, { userId: sessionUser?.id || null, cid });
      return sendJSON(res,200,{ posts });
    }
    if(pathname==='/api/posts' && method==='POST'){
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'login-required' });
      const config = typeof store.getConfig === 'function' ? await store.getConfig() : { basicPostingRestricted: false };
      if(config?.basicPostingRestricted && !isAdminUser(sessionUser)){
        return sendJSON(res,403,{ error:'posting-restricted', message:'현재는 관리자만 게시물을 작성할 수 있습니다.' });
      }
      const body = await parseBody(req);
      let attachments = [];
      try{
        attachments = await prepareAttachments(body.attachments);
      }catch(err){
        if(err && err.code === 'file-too-large') return sendJSON(res,413,{ error:'attachment-too-large' });
        if(err && err.code === 'attachment-invalid') return sendJSON(res,400,{ error:'attachment-invalid' });
        if(err && err.code === 'poll-invalid') return sendJSON(res,400,{ error:'poll-invalid' });
        throw err;
      }
      const post = await store.createPost({ user: sessionUser, text: body.text, attachments });
      const presented = presentPostForClient(post, { userId: sessionUser.id, cid });
      return sendJSON(res,200,{ saved:true, post: presented });
    }
    const postIdMatch = pathname.match(/^\/api\/posts\/([^/]+)$/);
    if(postIdMatch){
      const postId = postIdMatch[1];
      if(method==='PUT'){
        const sid = cookies['sid'];
        const sessionUser = await store.getSessionUser(sid);
        if(!sessionUser) return sendJSON(res,401,{ error:'login-required' });
        const existing = await store.getPostById?.(postId);
        if(!existing) return sendJSON(res,404,{ error:'post-not-found' });
        if(existing.author?.id !== sessionUser.id) return sendJSON(res,403,{ error:'forbidden' });
        const body = await parseBody(req);
        const updatePayload = { text: body.text };
        if(Object.prototype.hasOwnProperty.call(body, 'attachments')){
          try{
            updatePayload.attachments = await prepareAttachments(body.attachments);
          }catch(err){
            if(err && err.code === 'file-too-large') return sendJSON(res,413,{ error:'attachment-too-large' });
            if(err && err.code === 'attachment-invalid') return sendJSON(res,400,{ error:'attachment-invalid' });
            if(err && err.code === 'poll-invalid') return sendJSON(res,400,{ error:'poll-invalid' });
            throw err;
          }
        }
        const updated = await store.updatePost?.(postId, updatePayload);
        if(!updated) return sendJSON(res,404,{ error:'post-not-found' });
        const presented = presentPostForClient(updated, { userId: sessionUser.id, cid });
        return sendJSON(res,200,{ ok:true, post: presented });
      }
      if(method==='DELETE'){
        const sid = cookies['sid'];
        const sessionUser = await store.getSessionUser(sid);
        if(!sessionUser) return sendJSON(res,401,{ error:'login-required' });
        const existing = await store.getPostById?.(postId);
        if(!existing) return sendJSON(res,404,{ error:'post-not-found' });
        if(existing.author?.id !== sessionUser.id) return sendJSON(res,403,{ error:'forbidden' });
        await store.deletePost?.(postId);
        return sendJSON(res,200,{ ok:true });
      }
    }

    const pollVoteMatch = pathname.match(/^\/api\/posts\/([^/]+)\/polls\/([^/]+)\/vote$/);
    if(pollVoteMatch && method==='POST'){
      if(typeof store.voteOnPoll !== 'function') return sendJSON(res,501,{ error:'poll-not-supported' });
      const [ , postId, pollId ] = pollVoteMatch;
      const body = await parseBody(req);
      const optionId = String(body.optionId || '').trim();
      if(!optionId) return sendJSON(res,400,{ error:'option-required' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      try{
        const result = await store.voteOnPoll({
          postId,
          pollId,
          optionId,
          userId: sessionUser?.id || null,
          cid,
        });
        const poll = presentPollFromPost(result?.post, pollId, { userId: sessionUser?.id || null, cid });
        return sendJSON(res,200,{ ok:true, poll });
      }catch(err){
        if(err && err.code === 'post-not-found') return sendJSON(res,404,{ error:'post-not-found' });
        if(err && err.code === 'poll-not-found') return sendJSON(res,404,{ error:'poll-not-found' });
        if(err && err.code === 'option-not-found') return sendJSON(res,400,{ error:'option-not-found' });
        if(err && err.code === 'already-voted') return sendJSON(res,409,{ error:'already-voted' });
        if(err && err.code === 'identity-required') return sendJSON(res,403,{ error:'vote-not-allowed' });
        throw err;
      }
    }

    const reportMatch = pathname.match(/^\/api\/posts\/([^/]+)\/report$/);
    if(reportMatch && method==='POST'){
      if(typeof store.createReport !== 'function') return sendJSON(res,501,{ error:'report-not-supported' });
      const postId = reportMatch[1];
      const body = await parseBody(req);
      const reason = String(body.reason || '').trim();
      const detail = body.detail ? String(body.detail).trim() : '';
      if(!reason) return sendJSON(res,400,{ error:'reason-required' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      if(!sessionUser) return sendJSON(res,401,{ error:'login-required' });
      try{
        await store.createReport({
          postId,
          reason,
          detail,
          reporter: sessionUser
            ? { type:'user', user: sessionUser }
            : null,
        });
        return sendJSON(res,200,{ ok:true });
      }catch(err){
        if(err && err.code === 'post-not-found') return sendJSON(res,404,{ error:'post-not-found' });
        return sendJSON(res,400,{ error:'report-failed' });
      }
    }

    // Comments
    if(pathname==='/api/comments' && method==='POST'){
      const body = await parseBody(req);
      if(!body.postId) return sendJSON(res,400,{ error:'post-required' });
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      const config = typeof store.getConfig === 'function'
        ? await store.getConfig()
        : { allowAnon: true, basicPostingRestricted: false };
      const writeLocked = !!config.basicPostingRestricted;

      // member comment
      if(sessionUser){
        if(writeLocked && !isAdminUser(sessionUser)){
          return sendJSON(res,403,{ error:'posting-restricted', message:'현재는 관리자만 댓글을 작성할 수 있습니다.' });
        }
        const comment = await store.createComment({
          postId: body.postId,
          payload: { authorType:'user', user: sessionUser, text: body.text },
        });
        if(!comment) return sendJSON(res,404,{ error:'post-not-found' });
        return sendJSON(res,200,{ saved:true, comment });
      }

      // guest comment
      if(writeLocked){
        return sendJSON(res,403,{ error:'posting-restricted', message:'현재는 관리자만 댓글을 작성할 수 있습니다.' });
      }
      if(!config.allowAnon) return sendJSON(res,403,{ error:'anon-disabled' });
      // per-client limit using cid
      const client = await store.getClient(cid);
      if(client && client.guestUsed) return sendJSON(res,403,{ error:'guest-limit' });
      const pw = String(body.guestPw||'');
      if(!/^\d{4}$/.test(pw)) return sendJSON(res,400,{ error:'pw-bad' });
      const comment = await store.createComment({
        postId: body.postId,
        payload: { authorType:'guest', text: body.text, guestPwHash: sha256(pw) },
      });
      if(!comment) return sendJSON(res,404,{ error:'post-not-found' });
      await store.markClientGuestUsed(cid);
      return sendJSON(res,200,{ saved:true, comment });
    }

    // PUT/DELETE /api/comments/:id
    const cm = pathname.match(/^\/api\/comments\/([^/]+)$/);
    if(cm && method==='PUT'){
      const commentId = cm[1];
      const body = await parseBody(req);
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      const data = await store.getCommentById(commentId);
      const comment = data && data.comment;
      if(!comment) return sendJSON(res,404,{ error:'not-found' });

      // auth check
      if(comment.authorType==='user'){
        if(!(sessionUser && comment.author && comment.author.id===sessionUser.id)) return sendJSON(res,403,{ error:'forbidden' });
      }else{
        const pw = String(body.guestPw||''); if(!/^\d{4}$/.test(pw)) return sendJSON(res,400,{ error:'pw-bad' });
        if(sha256(pw)!==comment.guestPwHash) return sendJSON(res,403,{ error:'pw-mismatch' });
      }

      const updated = await store.updateComment(commentId, { text: body.text });
      return sendJSON(res,200,{ saved:true, comment: updated || comment });
    }
    if(cm && method==='DELETE'){
      const commentId = cm[1];
      const body = await parseBody(req);
      const sid = cookies['sid'];
      const sessionUser = await store.getSessionUser(sid);
      const data = await store.getCommentById(commentId);
      const comment = data && data.comment;
      if(!comment) return sendJSON(res,404,{ error:'not-found' });
      const adminOverride = sessionUser && isAdminUser(sessionUser);

      if(comment.authorType==='user'){
        const isOwner = sessionUser && comment.author && comment.author.id===sessionUser.id;
        if(!(isOwner || adminOverride)) return sendJSON(res,403,{ error:'forbidden' });
      }else{
        if(!adminOverride){
          const pw = String(body.guestPw||'');
          if(!/^\d{4}$/.test(pw)) return sendJSON(res,400,{ error:'pw-bad' });
          if(sha256(pw)!==comment.guestPwHash) return sendJSON(res,403,{ error:'pw-mismatch' });
        }
      }
      await store.deleteComment(commentId);
      return sendJSON(res,200,{ deleted:true, moderated: !!adminOverride });
    }

    // ---- Static files
    if(pathname==='/') return serveStatic(req,res,'/home.html');
    return serveStatic(req,res,pathname);

  }catch(err){
    if(err && err.code === 'account-disabled'){
      console.error('Account schema not ready', err.message);
      return sendJSON(res,503,{ error:'account-disabled', message: err.message });
    }
    if(err && err.code === 'notifications-disabled'){
      console.error('Notifications schema not ready', err.message);
      return sendJSON(res,503,{ error:'notifications-disabled', message: err.message });
    }
    console.error(err);
    send(res, 500, 'Internal Server Error');
  }
});

module.exports = server;

// 로컬 개발 환경에서만 서버를 직접 실행합니다.
if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
  });
}
