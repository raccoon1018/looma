const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

const R2_BUCKET = (process.env.LOOMA_R2_BUCKET || '').trim();

function extractAccountId(value) {
  if (!value) return '';
  const trimmed = String(value).trim();
  if (/^[a-f0-9]{32}$/i.test(trimmed)) return trimmed;
  try {
    const parsed = new URL(trimmed);
    const host = parsed.hostname || '';
    const direct = host.match(/^([a-f0-9]{32})\.r2\.cloudflarestorage\.com$/i);
    if (direct) return direct[1];
    const pub = host.match(/^pub-([a-f0-9]{32})\.r2\.dev$/i);
    if (pub) return pub[1];
  } catch {
    /* ignore */
  }
  return '';
}

function computeR2PublicBase() {
  const endpointRaw = (process.env.LOOMA_R2_ENDPOINT || '').trim();
  const accountIdEnv = (process.env.LOOMA_R2_ACCOUNT_ID || '').trim();
  const accountIdFromEndpoint = extractAccountId(endpointRaw);
  const accountId = accountIdEnv || accountIdFromEndpoint;
  const publicBaseEnv = (process.env.LOOMA_R2_PUBLIC_BASE || '').trim();

  const candidates = [];
  if (publicBaseEnv) candidates.push(publicBaseEnv);
  if (accountId && R2_BUCKET) {
    candidates.push(`https://pub-${accountId}.r2.dev/${R2_BUCKET}`);
    candidates.push(`https://${accountId}.r2.cloudflarestorage.com/${R2_BUCKET}`);
  }
  if (endpointRaw && R2_BUCKET) {
    try {
      const endpointUrl = new URL(endpointRaw);
      const base = `${endpointUrl.protocol}//${endpointUrl.host}`;
      if (endpointRaw.endsWith(`/${R2_BUCKET}`)) {
        candidates.push(endpointRaw);
      } else {
        candidates.push(`${base}/${R2_BUCKET}`);
      }
    } catch {
      if (endpointRaw.endsWith(`/${R2_BUCKET}`)) {
        candidates.push(endpointRaw);
      } else {
        candidates.push(`${endpointRaw}/${R2_BUCKET}`);
      }
    }
  }
  const resolved = (candidates.find(Boolean) || '').replace(/\/+$/, '');
  return resolved;
}

const R2_PUBLIC_BASE = computeR2PublicBase();

const DEFAULT_MESSAGE_GROUP_SEEDS = [
  {
    id: 'grp_music',
    type: 'group',
    name: '음악 감상실',
    desc: '새 음악과 공연 소식을 나눠요',
    tags: ['문화', '취향'],
    avatar: '🎧',
    locked: false,
  },
  {
    id: 'grp_study',
    type: 'group',
    name: '스터디 포럼',
    desc: '스터디 모집과 학습 자료를 공유해요',
    tags: ['학습', '커리어'],
    avatar: '📚',
    locked: false,
  },
  {
    id: 'grp_makers',
    type: 'group',
    name: '메이커스 라운지',
    desc: '사이드 프로젝트와 제작 노하우를 나눠요',
    tags: ['프로덕트', '제작'],
    avatar: '🛠️',
    locked: false,
  },
];

function extractHashtags(text) {
  if (!text || typeof text !== 'string') return [];
  const matches = text.match(/#[0-9A-Za-z가-힣_]{1,50}/g);
  if (!matches) return [];
  return matches
    .map((tag) => `#${tag.replace(/^#+/, '').toLowerCase()}`)
    .filter((tag) => tag.length > 1);
}

function aggregateHashtagCounts(posts) {
  const counts = new Map();
  for (const post of posts || []) {
    const text = post?.text || '';
    const tags = extractHashtags(text);
    if (!tags.length) continue;
    tags.forEach((tag) => counts.set(tag, (counts.get(tag) || 0) + 1));
  }
  return counts;
}

function presentUserForExplore(user) {
  if (!user) return null;
  return {
    id: user.id,
    handle: user.handle || null,
    name: user.name || null,
    avatarUrl: user.avatarUrl || null,
    createdAt: user.createdAt || null,
  };
}

function ensureUserActionStructure(db) {
  db.userActions ||= [];
}

function recordUserActionLocal(db, uidFn, { userId, action, reason, detail, actorId, actorType, metadata }) {
  ensureUserActionStructure(db);
  const actor = actorId && db.users ? db.users[actorId] : null;
  const entry = {
    id: 'act_' + uidFn(8),
    userId,
    action,
    reason: reason || null,
    detail: detail || null,
    actorId: actorId || null,
    actorHandle: actor?.handle || null,
    actorType: actorType || (actorId ? 'user' : 'system'),
    metadata: metadata || null,
    createdAt: new Date().toISOString(),
  };
  db.userActions.push(entry);
  if (userId && shouldNotifyAdminAction(action)) {
    appendNotificationLocal(db, uidFn, {
      userId,
      type: 'admin-action',
      actorId: actorId || null,
      postId: null,
      commentId: null,
      payload: buildAdminActionNotificationPayload(action, { reason, detail }),
    });
  }
}

function ensureNotificationStructure(db) {
  db.notifications ||= [];
}

function appendNotificationLocal(db, uidFn, { userId, type, actorId, postId, commentId, payload }) {
  if (!db || !userId || !type) return null;
  ensureNotificationStructure(db);
  const notification = {
    id: 'noti_' + uidFn(8),
    userId,
    type,
    actorId: actorId || null,
    postId: postId || null,
    commentId: commentId || null,
    payload: payload || null,
    createdAt: new Date().toISOString(),
    seenAt: null,
  };
  db.notifications.push(notification);
  return notification;
}

const ADMIN_ACTION_NOTIFY_SET = new Set([
  'warned',
  'content-removed',
  'promoted-admin',
  'demoted-admin',
  'restored',
]);

function shouldNotifyAdminAction(action) {
  return ADMIN_ACTION_NOTIFY_SET.has(action);
}

function describeAdminAction(action) {
  switch (action) {
    case 'warned':
      return { title: '경고 조치 안내', message: '커뮤니티 가이드 위반 우려로 경고가 적용되었습니다.' };
    case 'content-removed':
      return { title: '게시물 삭제 안내', message: '작성하신 게시물이 가이드라인에 따라 삭제되었습니다.' };
    case 'promoted-admin':
      return { title: '관리자 권한 부여', message: '관리자 권한이 부여되었습니다. 관리 기능을 책임감 있게 사용해 주세요.' };
    case 'demoted-admin':
      return { title: '관리자 권한 해제', message: '관리자 권한이 해제되었습니다.' };
    case 'restored':
      return { title: '조치 해제 안내', message: '계정에 적용된 조치가 해제되었습니다.' };
    default:
      return { title: '관리 조치 안내', message: '관리 조치가 적용되었습니다.' };
  }
}

function buildAdminActionNotificationPayload(action, { reason, detail } = {}) {
  const meta = describeAdminAction(action);
  return {
    action,
    title: meta.title,
    message: meta.message,
    reason: reason || null,
    detail: detail || null,
    advisory: '안전하고 건강한 커뮤니티를 위해 가이드라인을 준수해 주세요.',
  };
}

function purgeUserContentLocal(db, userId) {
  if (!db || !userId) return { postsRemoved: 0, commentsRemoved: 0 };
  let postsRemoved = 0;
  let commentsRemoved = 0;
  if (!Array.isArray(db.posts)) {
    return { postsRemoved, commentsRemoved };
  }
  db.posts = db.posts
    .map((post) => {
      if (!post) return post;
      if (post.author && post.author.id === userId) {
        postsRemoved += 1;
        return null;
      }
      if (Array.isArray(post.comments) && post.comments.length) {
        const filtered = post.comments.filter((comment) => {
          if (!comment || comment.authorType !== 'user') return true;
          return !(comment.author && comment.author.id === userId);
        });
        commentsRemoved += post.comments.length - filtered.length;
        post.comments = filtered;
      }
      return post;
    })
    .filter(Boolean);
  if (Array.isArray(db.notifications)) {
    db.notifications = db.notifications.filter(
      (entry) => entry && entry.userId !== userId && entry.actorId !== userId,
    );
  }
  return { postsRemoved, commentsRemoved };
}

function ensureUserAccountDefaults(db) {
  ensureUserActionStructure(db);
  Object.values(db.users || {}).forEach((user) => {
    if (!user) return;
    user.status = user.status || 'active';
    if (user.deactivatedAt === undefined) user.deactivatedAt = null;
    if (user.deletedAt === undefined) user.deletedAt = null;
    if (user.suspendedUntil === undefined) user.suspendedUntil = null;
    user.role = user.role || 'user';
    user.isSuperAdmin = !!(user.isSuperAdmin || user.role === 'superadmin');
  });
}

function ensureSystemConfig(db) {
  db.config ||= {};
  if (db.config.allowAnon === undefined) db.config.allowAnon = true;
  const mode = db.config.registrationMode;
  if (mode !== 'invite' && mode !== 'open') {
    db.config.registrationMode = 'open';
  }
  if (db.config.basicPostingRestricted === undefined) {
    db.config.basicPostingRestricted = false;
  }
}

function ensureAnnouncementsStructure(db) {
  if (!Array.isArray(db.announcements)) db.announcements = [];
  db.announcements = db.announcements
    .filter(Boolean)
    .map((entry) => ({
      id: entry.id || `ann_${Math.random().toString(36).slice(2, 10)}`,
      title: String(entry.title || '').trim(),
      body: String(entry.body || '').trim(),
      pinned: !!entry.pinned,
      createdAt: entry.createdAt || new Date().toISOString(),
      updatedAt: entry.updatedAt || entry.createdAt || new Date().toISOString(),
      createdBy: entry.createdBy || null,
      updatedBy: entry.updatedBy || entry.createdBy || null,
    }));
}

function ensureReferralCodesStructure(db) {
  if (!Array.isArray(db.referralCodes)) db.referralCodes = [];
  db.referralCodes = db.referralCodes
    .filter(Boolean)
    .map((entry) => {
      const limitRaw =
        entry.limit === 'unlimited' || entry.limit === null || entry.limit === undefined
          ? null
          : Number(entry.limit);
      const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? limitRaw : null;
      const used = Number(entry.used || 0);
      return {
        code: String(entry.code || '').trim().toUpperCase(),
        createdAt: entry.createdAt || new Date().toISOString(),
        expiresAt: entry.expiresAt || null,
        limit,
        used: used > 0 ? used : 0,
        revoked: !!entry.revoked,
        metadata: entry.metadata || null,
        createdBy: entry.createdBy || null,
        lastUsedAt: entry.lastUsedAt || null,
        notes: entry.notes || null,
        usedBy: Array.isArray(entry.usedBy) ? entry.usedBy.filter(Boolean) : [],
      };
    });
}

function presentSystemConfig(rawConfig) {
  const allowAnon = !!(rawConfig?.allowAnon ?? true);
  const mode = rawConfig?.registrationMode === 'invite' ? 'invite' : 'open';
  const basicPostingRestricted = !!(rawConfig?.basicPostingRestricted ?? false);
  return {
    allowAnon,
    registrationMode: mode,
    requiresReferralCode: mode === 'invite',
    basicPostingRestricted,
  };
}

function ensureReportsStructure(db) {
  db.reports ||= [];
  db.reports = db.reports
    .filter(Boolean)
    .map((report) => {
      const next = { ...report };
      next.id = next.id || 'rpt_' + uid(8);
      next.type = next.type || (next.target?.type || 'post');
      next.status = next.status || 'open';
      next.createdAt = next.createdAt || new Date().toISOString();
      next.updatedAt = next.updatedAt || next.createdAt;
      if (!next.reporter && next.reporterUser) {
        next.reporter = {
          type: 'user',
          userId: next.reporterUser.id,
          handle: next.reporterUser.handle || null,
          name: next.reporterUser.name || null,
        };
      }
      if (next.reporter && !next.reporter.type) {
        next.reporter.type = 'user';
      }
      return next;
    });
}

function buildReportForAdmin(report, db) {
  const posts = Array.isArray(db?.posts) ? db.posts : [];
  const users = db?.users || {};
  const post = report.postId ? posts.find((p) => p.id === report.postId) : null;
  const targetUserId = report.target?.userId || post?.author?.id || null;
  const targetUser = targetUserId ? users[targetUserId] || null : null;
  const reporter = report.reporter || {};
  const summarySource = report.summary || post?.text || '';
  const targetHandle = report.target?.handle || targetUser?.handle || post?.author?.handle || null;
  const targetName = report.target?.name || targetUser?.name || post?.author?.name || null;
  return {
    id: report.id,
    type: report.type || 'post',
    status: report.status || 'open',
    reason: report.reason || null,
    detail: report.detail || null,
    summary: summarySource ? String(summarySource).slice(0, 160) : '',
    createdAt: report.createdAt || null,
    updatedAt: report.updatedAt || report.createdAt || null,
    reporter: {
      name: reporter.name || reporter.handle || null,
      handle: reporter.handle || null,
      userId: reporter.userId || reporter.user_id || null,
    },
    target: {
      type: report.target?.type || (report.postId ? 'post' : 'user'),
      id: report.target?.id || report.postId || null,
      userId: targetUserId,
      handle: targetHandle,
      name: targetName,
    },
    postId: report.postId || null,
  };
}

function sampleArray(array, limit) {
  const copy = Array.isArray(array) ? array.slice() : [];
  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  if (typeof limit === 'number' && Number.isFinite(limit) && limit >= 0) {
    return copy.slice(0, limit);
  }
  return copy;
}

function normalizeGroupTags(input) {
  const tokens = Array.isArray(input)
    ? input
    : typeof input === 'string'
    ? input.split(',')
    : [];
  const seen = new Set();
  const tags = [];
  for (const raw of tokens) {
    if (tags.length >= 6) break;
    let tag = String(raw || '').trim();
    if (!tag) continue;
    if (tag.startsWith('#')) tag = tag.slice(1);
    tag = tag.replace(/\s+/g, ' ');
    if (!tag) continue;
    const normalized = tag.slice(0, 32);
    const fingerprint = normalized.toLowerCase();
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    tags.push(normalized);
  }
  return tags;
}

function buildR2UrlFromKey(key) {
  if (!key) return null;
  if (!R2_PUBLIC_BASE) return null;
  const normalizedKey = String(key).replace(/^\/+/, '');
  return `${R2_PUBLIC_BASE}/${normalizedKey}`;
}

function deriveKeyFromUrl(urlStr) {
  if (!urlStr) return null;
  try {
    const parsed = new URL(urlStr);
    let pathname = decodeURIComponent(parsed.pathname || '');
    if (pathname.startsWith('/')) pathname = pathname.slice(1);
    if (R2_BUCKET && pathname.startsWith(`${R2_BUCKET}/`)) {
      return pathname.slice(R2_BUCKET.length + 1);
    }
    return pathname;
  } catch {
    return null;
  }
}

function normalizeFileAttachment(att) {
  if (!att || typeof att !== 'object') return null;
  let key = att.key || null;
  if (!key && att.url) {
    key = deriveKeyFromUrl(att.url);
  }
  if (key) {
    key = String(key).replace(/^\/+/, '');
  }
  const resolvedUrl = buildR2UrlFromKey(key) || att.url || null;
  return {
    type: att.type || 'file',
    url: resolvedUrl,
    contentType: att.contentType || null,
    size: typeof att.size === 'number' ? att.size : att.size ? Number(att.size) : null,
    filename: att.filename || null,
    meta: att.meta || null,
    key: key || null,
    ext: att.ext || null,
  };
}

function normalizePollAttachment(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const nowIso = new Date().toISOString();
  const questionRaw = raw.question || raw.meta?.question || '';
  const question = String(questionRaw || '').trim();
  const optionsSrc = Array.isArray(raw.options)
    ? raw.options
    : Array.isArray(raw.meta?.options)
    ? raw.meta.options
    : [];

  const createOptionId = (pollIdValue, textValue, idx) => {
    const source = `${pollIdValue || ''}::${idx}::${textValue}`;
    const hash = crypto.createHash('sha256').update(source).digest('hex');
    return `opt_${hash.slice(0, 12)}`;
  };

  const votersUsers =
    raw.voters?.users && typeof raw.voters.users === 'object'
      ? { ...raw.voters.users }
      : {};
  const votersClients =
    raw.voters?.clients && typeof raw.voters.clients === 'object'
      ? { ...raw.voters.clients }
      : {};

  if (raw.pollId && Array.isArray(raw.options) && raw.options.some((opt) => typeof opt === 'object')) {
    const pollId = raw.pollId;
    const existingOptions = raw.options
      .map((opt, idx) => {
        const text = String(opt?.text ?? opt?.label ?? opt?.value ?? '').trim();
        if (!text) return null;
        const id = opt.id || createOptionId(pollId, text, idx);
        const count = Number.isFinite(opt.count) ? opt.count : Number(opt.count || 0) || 0;
        return { id, text, count };
      })
      .filter(Boolean);
    if (!raw.question && !question) return null;
    if (existingOptions.length < 2) return null;
    const totalVotes =
      Number(raw.totalVotes || 0) ||
      existingOptions.reduce((sum, opt) => sum + (Number(opt.count) || 0), 0);
    return {
      type: 'poll',
      pollId,
      question: raw.question || question,
      options: existingOptions,
      totalVotes,
      voters: { users: votersUsers, clients: votersClients },
      createdAt: raw.createdAt || nowIso,
    };
  }

  const optionStrings = optionsSrc
    .map((opt) => String(opt || '').trim())
    .filter((opt) => opt.length > 0);
  if (!question || optionStrings.length < 2) return null;
  let pollId = raw.pollId;
  if (!pollId) {
    const hashSource = `${question}::${optionStrings.join('||')}`;
    const hash = crypto.createHash('sha256').update(hashSource).digest('hex');
    pollId = `poll_${hash.slice(0, 12)}`;
  }
  const options = optionStrings.map((text, idx) => ({
    id: createOptionId(pollId, text, idx),
    text,
    count: 0,
  }));
  const totalVotes =
    Number(raw.totalVotes || 0) ||
    options.reduce((sum, opt) => sum + (Number(opt.count) || 0), 0);
  return {
    type: 'poll',
    pollId,
    question,
    options,
    totalVotes,
    voters: { users: votersUsers, clients: votersClients },
    createdAt: raw.createdAt || nowIso,
  };
}

function normalizeGroupName(raw) {
  const name = String(raw || '').trim();
  if (!name) {
    const err = new Error('그룹 이름을 입력해 주세요.');
    err.code = 'invalid-name';
    throw err;
  }
  if (name.length < 2) {
    const err = new Error('그룹 이름은 최소 2자 이상이어야 합니다.');
    err.code = 'invalid-name';
    throw err;
  }
  if (name.length > 60) {
    const err = new Error('그룹 이름은 60자를 넘을 수 없습니다.');
    err.code = 'invalid-name';
    throw err;
  }
  return name;
}

  function normalizeGroupDesc(raw) {
    if (!raw) return '';
    const desc = String(raw).trim();
    return desc.slice(0, 200);
  }

  function ensureUserFollowStructure(db) {
  db.userFollows ||= [];
  const unique = [];
  const seen = new Set();
  (db.userFollows || []).forEach((entry) => {
    if (!entry) return;
    const followerId = entry.followerId || entry.follower_id;
    const targetId = entry.targetId || entry.target_id;
    if (!followerId || !targetId || followerId === targetId) return;
    const key = `${followerId}::${targetId}`;
    if (seen.has(key)) return;
    seen.add(key);
    unique.push({
      followerId,
      targetId,
      createdAt: entry.createdAt || entry.created_at || new Date().toISOString(),
    });
  });
  db.userFollows = unique;
}

function isFollowingLocal(db, followerId, targetId) {
  if (!followerId || !targetId) return false;
  return (db.userFollows || []).some((entry) => entry && entry.followerId === followerId && entry.targetId === targetId);
}

function computeFollowStatsLocal(db, userId) {
  const stats = { followers: 0, following: 0 };
  if (!userId) return stats;
  (db.userFollows || []).forEach((entry) => {
    if (!entry) return;
    if (entry.targetId === userId) stats.followers += 1;
    if (entry.followerId === userId) stats.following += 1;
  });
  return stats;
}

function clonePollForClient(poll, { viewerUserId, viewerCid } = {}) {
  if (!poll || poll.type !== 'poll') return null;
  const totalVotes = Number(poll.totalVotes || 0) || 0;
  const usersMap = poll.voters?.users || {};
  const clientsMap = poll.voters?.clients || {};
  const viewerSelection =
    (viewerUserId && usersMap[viewerUserId]) ||
    (viewerCid && clientsMap[viewerCid]) ||
    null;
  const options = (poll.options || []).map((opt) => {
    const count = Number(opt.count || 0) || 0;
    const percent = totalVotes > 0 ? Number(((count / totalVotes) * 100).toFixed(2)) : 0;
    return {
      id: opt.id,
      text: opt.text,
      count,
      percent,
      isSelected: viewerSelection === opt.id,
    };
  });
  return {
    type: 'poll',
    pollId: poll.pollId,
    question: poll.question,
    options,
    optionIds: options.map((opt) => opt.id),
    optionTexts: options.map((opt) => opt.text),
    optionCounts: options.map((opt) => opt.count),
    optionPercents: options.map((opt) => opt.percent),
    totalVotes,
    viewerSelection,
    showResults: !!viewerSelection,
    createdAt: poll.createdAt || null,
  };
}

function cloneAttachmentForClient(att, viewer) {
  if (!att) return null;
  if (att.type === 'poll') {
    return clonePollForClient(att, viewer);
  }
  return normalizeFileAttachment(att);
}

function compactAuthor(user) {
  if (!user) return null;
  return {
    id: user.id,
    handle: user.handle || null,
    name: user.name || null,
    avatarUrl: user.avatarUrl || null,
  };
}

function toClientPost(post, viewer) {
  if (!post) return null;
  return {
    id: post.id,
    author: post.author ? { ...post.author } : null,
    text: post.text,
    createdAt: post.createdAt,
    attachments: (post.attachments || [])
      .map((att) => cloneAttachmentForClient(att, viewer))
      .filter(Boolean),
    comments: (post.comments || []).map((comment) => ({ ...comment })),
  };
}

function createStore({ dbPath, uid, sha256 }) {
  const mode = String(process.env.LOOMA_DATA_MODE || process.env.LOOMA_STORE_MODE || '').toLowerCase();
  if (mode === 'supabase') {
    return createSupabaseStore({ uid, sha256 });
  }
  return createFileStore({ dbPath, uid, sha256 });
}

module.exports = createStore;

// ===== File-based fallback store (default for local dev)
function createFileStore({ dbPath, uid, sha256 }) {
  const nowIso = new Date().toISOString();
  const initialDb = {
    config: { allowAnon: true, registrationMode: 'open', basicPostingRestricted: false },
    users: {
      u1: {
        id: 'u1',
        handle: '@looma_owner',
        name: '성민 윤',
        email: 'owner@looma.local',
        phone: '010-0000-0000',
        avatarUrl: null,
        passwordHash: sha256('looma'),
        createdAt: nowIso,
        status: 'active',
        deactivatedAt: null,
        deletedAt: null,
        suspendedUntil: null,
        role: 'superadmin',
        isSuperAdmin: true,
      },
    },
    sessions: {},
    clients: {},
    posts: [],
    reports: [],
    notifications: [],
    userFollows: [],
    userActions: [],
    announcements: [],
    referralCodes: [],
    messageChannels: [
      {
        id: 'square',
        type: 'square',
        name: '모두의 광장',
        desc: 'Looma 전체 공개 채널',
        tags: ['광장', '공지'],
        avatar: '🌐',
        locked: true,
        createdAt: nowIso,
        createdBy: null,
        members: [],
      },
      {
        id: 'grp_music',
        type: 'group',
        name: '음악 감상실',
        desc: '새 음악과 공연 소식을 나눠요',
        tags: ['문화', '취향'],
        avatar: '🎧',
        locked: false,
        createdAt: nowIso,
        createdBy: 'u1',
        members: [],
      },
      {
        id: 'grp_study',
        type: 'group',
        name: '스터디 포럼',
        desc: '스터디 모집과 학습 자료를 공유해요',
        tags: ['학습', '커리어'],
        avatar: '📚',
        locked: false,
        createdAt: nowIso,
        createdBy: 'u1',
        members: [],
      },
    ],
    messageMessages: [],
  };

  const normalizePollForStore = (raw) => normalizePollAttachment(raw);
  const normalizeAttachmentForStore = (att) => {
    if (att?.type === 'poll') return normalizePollForStore(att);
    return normalizeFileAttachment(att);
  };

  function ensureMessageDefaultsStructure(db) {
    db.messageChannels ||= [];
    db.messageMessages ||= [];
    const nowIso = new Date().toISOString();
    if (!db.messageChannels.find((c) => c && c.id === 'square')) {
      db.messageChannels.push({
        id: 'square',
        type: 'square',
        name: '모두의 광장',
        desc: 'Looma 전체 공개 채널',
        tags: ['광장', '공지'],
        avatar: '🌐',
        locked: true,
        createdAt: nowIso,
        createdBy: null,
        members: [],
      });
    }
    DEFAULT_MESSAGE_GROUP_SEEDS.forEach((seed) => {
      if (!db.messageChannels.find((c) => c && c.id === seed.id)) {
        db.messageChannels.push({
          id: seed.id,
          type: seed.type,
          name: seed.name,
          desc: seed.desc,
          tags: Array.isArray(seed.tags) ? [...seed.tags] : [],
          avatar: seed.avatar || null,
          locked: !!seed.locked,
          createdAt: nowIso,
          createdBy: 'u1',
          members: [],
        });
      }
    });
    db.messageChannels = db.messageChannels.map((channel) => {
      const next = { ...channel };
      if (!Array.isArray(next.members)) next.members = [];
      if (!Array.isArray(next.tags)) next.tags = [];
      if (!next.createdAt) next.createdAt = nowIso;
      if (typeof next.locked !== 'boolean') next.locked = false;
      return next;
    });
  }

  async function ensureReady() {
    try {
      await fsp.mkdir(path.dirname(dbPath), { recursive: true });
    } catch {
      /* ignore */
    }
    if (!fs.existsSync(dbPath)) {
      await fsp.writeFile(dbPath, JSON.stringify(initialDb, null, 2), 'utf8');
      return;
    }
    const raw = await fsp.readFile(dbPath, 'utf8');
    if (!raw.trim()) {
      await fsp.writeFile(dbPath, JSON.stringify(initialDb, null, 2), 'utf8');
      return;
    }
    const data = JSON.parse(raw);
    // Backfill password hash on existing user records
    Object.values(data.users || {}).forEach((user) => {
      if (!user.passwordHash) user.passwordHash = sha256('looma');
      if (!user.createdAt) user.createdAt = new Date().toISOString();
      if (user.handle === '@looma_owner') {
        if (!user.email) user.email = 'owner@looma.local';
        if (!user.phone) user.phone = '010-0000-0000';
      }
      if (user.avatarUrl === undefined) user.avatarUrl = null;
    });
    if (Array.isArray(data.posts) && data.posts.some((p) => typeof p.text === 'string' && p.text.includes('LOOMA 홈 피드 예제'))) {
      data.posts = [];
    }
    data.reports ||= [];
    ensureSystemConfig(data);
    ensureAnnouncementsStructure(data);
    ensureReferralCodesStructure(data);
    ensureNotificationStructure(data);
    ensureReportsStructure(data);
    if (Array.isArray(data.posts)) {
      data.posts.forEach((post) => {
        if (!Array.isArray(post.attachments)) {
          post.attachments = [];
        } else {
          post.attachments = post.attachments
            .map((att) => normalizeAttachmentForStore(att))
            .filter(Boolean);
        }
        if (!Array.isArray(post.comments)) {
          post.comments = [];
        }
        if (!post.status) post.status = 'active';
        if (!post.createdAt) post.createdAt = new Date().toISOString();
      });
    }
    ensureUserFollowStructure(data);
    ensureMessageDefaultsStructure(data);
    ensureUserAccountDefaults(data);
    await fsp.writeFile(dbPath, JSON.stringify(data, null, 2), 'utf8');
  }

  async function load() {
    await ensureReady();
    return JSON.parse(await fsp.readFile(dbPath, 'utf8'));
  }

  async function save(db) {
    await fsp.writeFile(dbPath, JSON.stringify(db, null, 2), 'utf8');
  }

  function presentAnnouncement(entry) {
    if (!entry) return null;
    return {
      id: entry.id,
      title: entry.title || '',
      body: entry.body || '',
      pinned: !!entry.pinned,
      createdAt: entry.createdAt || null,
      updatedAt: entry.updatedAt || entry.createdAt || null,
      createdBy: entry.createdBy || null,
      updatedBy: entry.updatedBy || null,
    };
  }

  function sortAnnouncements(list) {
    return list.sort((a, b) => {
      const pinDiff = Number(!!b.pinned) - Number(!!a.pinned);
      if (pinDiff !== 0) return pinDiff;
      const aTime = new Date(a?.createdAt || 0).getTime();
      const bTime = new Date(b?.createdAt || 0).getTime();
      return bTime - aTime;
    });
  }

  async function listAnnouncementsLocal({ pinnedOnly = false, limit } = {}) {
    const db = await load();
    ensureAnnouncementsStructure(db);
    const items = sortAnnouncements([...db.announcements]);
    const filtered = pinnedOnly ? items.filter((entry) => entry.pinned) : items;
    const limited =
      Number.isFinite(limit) && limit > 0 ? filtered.slice(0, Math.floor(limit)) : filtered;
    return limited.map(presentAnnouncement);
  }

  async function getAnnouncementLocal(id) {
    if (!id) return null;
    const db = await load();
    ensureAnnouncementsStructure(db);
    const entry = db.announcements.find((item) => item && item.id === id);
    return presentAnnouncement(entry);
  }

  async function createAnnouncementLocal({ title, body, pinned = false, actorId = null } = {}) {
    const db = await load();
    ensureAnnouncementsStructure(db);
    const nowIso = new Date().toISOString();
    const record = {
      id: `ann_${uid(8)}`,
      title: String(title || '').trim(),
      body: String(body || '').trim(),
      pinned: !!pinned,
      createdAt: nowIso,
      updatedAt: nowIso,
      createdBy: actorId || null,
      updatedBy: actorId || null,
    };
    db.announcements.unshift(record);
    await save(db);
    return presentAnnouncement(record);
  }

  async function updateAnnouncementLocal(
    id,
    { title, body, pinned, actorId = null } = {},
  ) {
    if (!id) return null;
    const db = await load();
    ensureAnnouncementsStructure(db);
    const idx = db.announcements.findIndex((entry) => entry && entry.id === id);
    if (idx < 0) return null;
    const record = db.announcements[idx];
    if (title !== undefined) record.title = String(title || '').trim();
    if (body !== undefined) record.body = String(body || '').trim();
    if (pinned !== undefined) record.pinned = !!pinned;
    record.updatedAt = new Date().toISOString();
    record.updatedBy = actorId || record.updatedBy || null;
    db.announcements[idx] = record;
    await save(db);
    return presentAnnouncement(record);
  }

  async function deleteAnnouncementLocal(id) {
    if (!id) return false;
    const db = await load();
    ensureAnnouncementsStructure(db);
    const before = db.announcements.length;
    db.announcements = db.announcements.filter((entry) => entry && entry.id !== id);
    const changed = db.announcements.length !== before;
    if (changed) await save(db);
    return changed;
  }

  function presentReferralCodeEntry(entry) {
    if (!entry) return null;
    return {
      code: entry.code,
      createdAt: entry.createdAt || null,
      expiresAt: entry.expiresAt || null,
      limit: entry.limit ?? 'unlimited',
      used: entry.used || 0,
      revoked: !!entry.revoked,
      createdBy: entry.createdBy || null,
      lastUsedAt: entry.lastUsedAt || null,
      metadata: entry.metadata || null,
      notes: entry.notes || null,
      usedBy: Array.isArray(entry.usedBy) ? [...entry.usedBy] : [],
    };
  }

  function isReferralCodeUsable(entry) {
    if (!entry) return { ok: false, reason: 'not-found' };
    if (entry.revoked) return { ok: false, reason: 'revoked' };
    const now = Date.now();
    if (entry.expiresAt) {
      const exp = new Date(entry.expiresAt).getTime();
      if (Number.isFinite(exp) && now > exp) return { ok: false, reason: 'expired' };
    }
    if (Number.isFinite(entry.limit) && entry.limit >= 0 && entry.used >= entry.limit) {
      return { ok: false, reason: 'limit-reached' };
    }
    return { ok: true, reason: null };
  }

  async function listReferralCodesLocal() {
    const db = await load();
    ensureReferralCodesStructure(db);
    const list = [...db.referralCodes].sort(
      (a, b) => new Date(b?.createdAt || 0).getTime() - new Date(a?.createdAt || 0).getTime(),
    );
    return list.map(presentReferralCodeEntry);
  }

  async function createReferralCodeLocal({
    prefix = '',
    expiresAt = null,
    limit = null,
    actorId = null,
    notes = null,
  } = {}) {
    const db = await load();
    ensureReferralCodesStructure(db);
    const normalizedPrefix = String(prefix || '')
      .trim()
      .replace(/[^0-9A-Za-z]/g, '')
      .toUpperCase();
    let code;
    do {
      const base = uid(4).toUpperCase();
      code = normalizedPrefix ? `${normalizedPrefix}-${base}` : base;
    } while (db.referralCodes.find((entry) => entry && entry.code === code));
    const nowIso = new Date().toISOString();
    let expiresIso = null;
    if (expiresAt) {
      const parsed = new Date(expiresAt);
      if (Number.isFinite(parsed.getTime())) {
        expiresIso = parsed.toISOString();
      }
    }
    let limitNormalized = null;
    if (limit !== null && limit !== undefined && limit !== 'unlimited') {
      const numeric = Number(limit);
      if (Number.isFinite(numeric) && numeric > 0) {
        limitNormalized = Math.floor(numeric);
      }
    }
    const record = {
      code,
      createdAt: nowIso,
      expiresAt: expiresIso,
      limit: limitNormalized,
      used: 0,
      revoked: false,
      metadata: null,
      createdBy: actorId || null,
      lastUsedAt: null,
      notes: notes || null,
      usedBy: [],
    };
    db.referralCodes.unshift(record);
    await save(db);
    return presentReferralCodeEntry(record);
  }

  async function revokeReferralCodeLocal(code) {
    if (!code) return false;
    const normalized = String(code || '').trim().toUpperCase();
    const db = await load();
    ensureReferralCodesStructure(db);
    const record = db.referralCodes.find((entry) => entry && entry.code === normalized);
    if (!record) return false;
    if (!record.revoked) {
      record.revoked = true;
      record.updatedAt = new Date().toISOString();
      await save(db);
    }
    return true;
  }

  async function verifyReferralCodeLocal(code) {
    if (!code) {
      return { valid: false, reason: 'required', code: null };
    }
    const normalized = String(code || '').trim().toUpperCase();
    const db = await load();
    ensureReferralCodesStructure(db);
    const record = db.referralCodes.find((entry) => entry && entry.code === normalized);
    if (!record) return { valid: false, reason: 'not-found', code: null };
    const status = isReferralCodeUsable(record);
    return {
      valid: status.ok,
      reason: status.reason,
      code: presentReferralCodeEntry(record),
    };
  }

  async function consumeReferralCodeLocal(code, { userId = null } = {}) {
    if (!code) return { ok: false, reason: 'required' };
    const normalized = String(code || '').trim().toUpperCase();
    const db = await load();
    ensureReferralCodesStructure(db);
    const record = db.referralCodes.find((entry) => entry && entry.code === normalized);
    if (!record) return { ok: false, reason: 'not-found' };
    const status = isReferralCodeUsable(record);
    if (!status.ok) return { ok: false, reason: status.reason };
    record.used += 1;
    record.lastUsedAt = new Date().toISOString();
    if (userId) {
      record.usedBy = Array.isArray(record.usedBy) ? record.usedBy : [];
      record.usedBy.push({ userId, usedAt: record.lastUsedAt });
    }
    await save(db);
    return { ok: true, code: presentReferralCodeEntry(record) };
  }

  async function getLatestAccountActionLocal(userId) {
    if (!userId) return null;
    const db = await load();
    ensureUserAccountDefaults(db);
    ensureUserActionStructure(db);
    const entry = (db.userActions || [])
      .filter((action) => action && action.userId === userId)
      .sort((a, b) => new Date(b?.createdAt || 0) - new Date(a?.createdAt || 0))[0];
    if (!entry) return null;
    const actor =
      entry.actorId && db.users?.[entry.actorId]
        ? {
            id: entry.actorId,
            handle: db.users[entry.actorId]?.handle || null,
            name: db.users[entry.actorId]?.name || null,
          }
        : null;
    return {
      id: entry.id,
      userId: entry.userId,
      action: entry.action,
      reason: entry.reason || null,
      detail: entry.detail || null,
      actor,
      actorType: entry.actorType || null,
      createdAt: entry.createdAt || null,
      metadata: entry.metadata || null,
    };
  }

  function publicUser(user) {
    if (!user) return null;
    const { passwordHash, ...rest } = user;
    return {
      ...rest,
      status: rest.status || 'active',
      deactivatedAt: rest.deactivatedAt || null,
      deletedAt: rest.deletedAt || null,
      suspendedUntil: rest.suspendedUntil || null,
      role: rest.role || null,
      isSuperAdmin: !!rest.isSuperAdmin,
    };
  }

  function buildViewerFollowSets(db, viewerId) {
    const sets = {
      following: new Set(),
      followers: new Set(),
    };
    if (!viewerId) return sets;
    (db.userFollows || []).forEach((entry) => {
      if (!entry) return;
      if (entry.followerId === viewerId) {
        sets.following.add(entry.targetId);
      }
      if (entry.targetId === viewerId) {
        sets.followers.add(entry.followerId);
      }
    });
    return sets;
  }

  function clampFollowLimit(limit) {
    if (!Number.isFinite(limit)) return 50;
    if (limit <= 0) return null;
    return Math.min(Math.floor(limit), 200);
  }

  async function listFollowersLocal(userId, { viewerId, limit = 50 } = {}) {
    if (!userId) return [];
    const db = await load();
    ensureUserFollowStructure(db);
    const safeLimit = clampFollowLimit(limit);
    const entries = (db.userFollows || [])
      .filter((entry) => entry && entry.targetId === userId)
      .sort((a, b) => {
        const aTime = new Date(a?.createdAt || 0).getTime();
        const bTime = new Date(b?.createdAt || 0).getTime();
        return bTime - aTime;
      });
    const sliced = safeLimit ? entries.slice(0, safeLimit) : entries;
    const viewerSets = buildViewerFollowSets(db, viewerId);
    return sliced
      .map((entry) => {
        const follower = db.users?.[entry.followerId];
        if (!follower) return null;
        const user = publicUser(follower);
        const isFollowing = viewerId ? viewerSets.following.has(follower.id) : false;
        const isMutual = viewerId
          ? viewerSets.following.has(follower.id) && viewerSets.followers.has(follower.id)
          : false;
        return {
          user,
          followedAt: entry.createdAt || null,
          isFollowing,
          isMutual,
        };
      })
      .filter(Boolean);
  }

  async function listFollowingLocal(userId, { viewerId, limit = 50 } = {}) {
    if (!userId) return [];
    const db = await load();
    ensureUserFollowStructure(db);
    const safeLimit = clampFollowLimit(limit);
    const entries = (db.userFollows || [])
      .filter((entry) => entry && entry.followerId === userId)
      .sort((a, b) => {
        const aTime = new Date(a?.createdAt || 0).getTime();
        const bTime = new Date(b?.createdAt || 0).getTime();
        return bTime - aTime;
      });
    const sliced = safeLimit ? entries.slice(0, safeLimit) : entries;
    const viewerSets = buildViewerFollowSets(db, viewerId);
    return sliced
      .map((entry) => {
        const target = db.users?.[entry.targetId];
        if (!target) return null;
        const user = publicUser(target);
        const isFollowing = viewerId ? viewerSets.following.has(target.id) : false;
        const isMutual = viewerId ? viewerSets.followers.has(target.id) : false;
        return {
          user,
          followedAt: entry.createdAt || null,
          isFollowing,
          isMutual,
        };
      })
      .filter(Boolean);
  }

  async function searchUsersLocal({ query, viewerId, excludeIds, limit = 10 } = {}) {
    const raw = String(query || '').trim();
    if (!raw) return [];
    const db = await load();
    const excludeSet = new Set(Array.isArray(excludeIds) ? excludeIds.filter(Boolean) : []);
    const normalized = raw.toLowerCase();
    const handleSearch = normalized.startsWith('@') ? normalized.replace(/^@+/, '') : null;
    const candidates = Object.values(db.users || {})
      .filter((user) => {
        if (!user) return false;
        if (excludeSet.has(user.id)) return false;
        const handle = (user.handle || '').toLowerCase();
        const name = (user.name || '').toLowerCase();
        if (handleSearch) {
          return handle.includes(`@${handleSearch}`) || handle.includes(handleSearch);
        }
        return handle.includes(normalized) || name.includes(normalized);
      })
      .sort((a, b) => {
        const an = (a.name || a.handle || '').toLowerCase();
        const bn = (b.name || b.handle || '').toLowerCase();
        return an.localeCompare(bn);
      });
    const limited = candidates.slice(0, Math.min(Math.max(limit || 0, 1), 50));
    return limited.map((user) => {
      const publicEntry = publicUser(user);
      const presented = presentUserForExplore(publicEntry);
      return {
        ...presented,
        isFollowing: viewerId ? isFollowingLocal(db, viewerId, user.id) : false,
        isSelf: viewerId ? viewerId === user.id : false,
      };
    });
  }

  async function listRandomUsersLocal({ viewerId, excludeIds, limit = 6 } = {}) {
    const db = await load();
    const excludeSet = new Set(Array.isArray(excludeIds) ? excludeIds.filter(Boolean) : []);
    if (viewerId) excludeSet.add(viewerId);
    const users = Object.values(db.users || {}).filter(
      (user) => user && !excludeSet.has(user.id),
    );
    const sampled = sampleArray(users, Math.min(Math.max(limit || 0, 0), 20));
    return sampled.map((user) => {
      const publicEntry = publicUser(user);
      const presented = presentUserForExplore(publicEntry);
      return {
        ...presented,
        isFollowing: viewerId ? isFollowingLocal(db, viewerId, user.id) : false,
        isSelf: viewerId ? viewerId === user.id : false,
      };
    });
  }

  async function searchPostsLocal({ query, tag, limit = 10 } = {}) {
    const raw = String(query || '').trim();
    const tagRaw = tag ? String(tag).replace(/^#/, '').toLowerCase() : null;
    if (!raw && !tagRaw) return [];
    const db = await load();
    const postsSource = Array.isArray(db.posts) ? db.posts.slice() : [];
    postsSource.sort(
      (a, b) =>
        new Date(b?.createdAt || 0).getTime() - new Date(a?.createdAt || 0).getTime(),
    );
    const results = [];
    const normalized = raw.toLowerCase();
    const handleSearch = normalized.startsWith('@')
      ? normalized.replace(/^@+/, '')
      : null;
    for (const post of postsSource) {
      if (results.length >= Math.min(Math.max(limit || 0, 1), 50)) break;
      if (!post) continue;
      const text = String(post.text || '');
      const authorId = post?.author?.id;
      const authorRecord = authorId ? db.users?.[authorId] || post.author : post.author;
      const authorHandle = String(authorRecord?.handle || '').toLowerCase();
      const tags = extractHashtags(text);
      const hasTag = tagRaw
        ? tags.some((t) => t.replace(/^#/, '') === tagRaw)
        : false;
      let matches = false;
      if (tagRaw) {
        matches = hasTag;
      }
      if (!matches && raw) {
        if (handleSearch) {
          matches = authorHandle.includes(handleSearch);
        } else {
          matches = text.toLowerCase().includes(normalized);
        }
      }
      if (!matches) continue;
      results.push({
        id: post.id,
        text,
        createdAt: post.createdAt || null,
        author: authorRecord ? compactAuthor(authorRecord) : null,
        tags,
      });
    }
    return results;
  }

  async function searchTagsLocal({ query, limit = 10 } = {}) {
    const db = await load();
    const counts = aggregateHashtagCounts(db.posts || []);
    if (!counts.size) return [];
    const entries = Array.from(counts.entries()).map(([tag, count]) => ({
      tag,
      count,
    }));
    const normalized = String(query || '').trim().toLowerCase();
    const filtered = normalized
      ? entries.filter((entry) =>
          entry.tag.includes(normalized.startsWith('#') ? normalized : `#${normalized}`),
        )
      : entries;
    return filtered
      .sort((a, b) => b.count - a.count)
      .slice(0, Math.min(Math.max(limit || 0, 1), 50));
  }

  async function getTrendingTagsLocal({ limit = 10 } = {}) {
    return searchTagsLocal({ query: '', limit });
  }

  function clonePollForClient(poll, { viewerUserId, viewerCid } = {}) {
    if (!poll || poll.type !== 'poll') return null;
    const totalVotes = Number(poll.totalVotes || 0) || 0;
    const usersMap = poll.voters?.users || {};
    const clientsMap = poll.voters?.clients || {};
    const viewerSelection =
      (viewerUserId && usersMap[viewerUserId]) ||
      (viewerCid && clientsMap[viewerCid]) ||
      null;
    const options = (poll.options || []).map((opt) => {
      const count = Number(opt.count || 0) || 0;
      const percent = totalVotes > 0 ? Number(((count / totalVotes) * 100).toFixed(2)) : 0;
      return {
        id: opt.id,
        text: opt.text,
        count,
        percent,
        isSelected: viewerSelection === opt.id,
      };
    });
    return {
      type: 'poll',
      pollId: poll.pollId,
      question: poll.question,
      options,
      optionIds: options.map((opt) => opt.id),
      optionTexts: options.map((opt) => opt.text),
      optionCounts: options.map((opt) => opt.count),
      optionPercents: options.map((opt) => opt.percent),
      totalVotes,
      viewerSelection,
      showResults: !!viewerSelection,
      createdAt: poll.createdAt || null,
    };
  }

  function cloneAttachmentForClient(att, viewer) {
    if (!att) return null;
    if (att.type === 'poll') {
      return clonePollForClient(att, viewer);
    }
    const cloned = normalizeFileAttachment(att);
    return cloned;
  }

  function toClientPost(post, viewer) {
    if (!post) return null;
    return {
      id: post.id,
      author: post.author ? { ...post.author } : null,
      text: post.text,
      createdAt: post.createdAt,
      attachments: (post.attachments || [])
        .map((att) => cloneAttachmentForClient(att, viewer))
        .filter(Boolean),
      comments: (post.comments || []).map((comment) => ({ ...comment })),
    };
  }

  function messageError(code, message) {
    const err = new Error(message || code);
    err.code = code;
    return err;
  }

  function mapMessageForClient(message, db) {
    if (!message) return null;
    const authorRaw = message.authorId ? db.users?.[message.authorId] : null;
    const author = authorRaw ? publicUser(authorRaw) : null;
    return {
      id: message.id,
      channelId: message.channelId,
      text: message.text,
      createdAt: message.createdAt,
      author: author
        ? {
            id: author.id,
            handle: author.handle,
            name: author.name,
            avatarUrl: author.avatarUrl || null,
          }
        : null,
    };
  }

  function selectChannelMessages(db, channelId) {
    return (db.messageMessages || [])
      .filter((msg) => msg && msg.channelId === channelId)
      .sort((a, b) => new Date(a.createdAt || 0) - new Date(b.createdAt || 0));
  }

  function buildAdminChannelEntryLocal(channel, db) {
    if (!channel || channel.id === 'square') return null;
    const members = Array.isArray(channel.members) ? channel.members : [];
    const users = db.users || {};
    const memberDetails = members.map((memberId) => {
      const data = presentUserForAdmin(users[memberId]);
      if (data) return data;
      return {
        id: memberId,
        handle: null,
        name: null,
        email: null,
        role: null,
        status: null,
        createdAt: null,
        suspendedUntil: null,
        isSuperAdmin: false,
      };
    });
    const messages = selectChannelMessages(db, channel.id);
    const lastMessage = messages.length ? messages[messages.length - 1] : null;
    const memberLabels = memberDetails
      .map((m) => m?.handle || m?.name || m?.id)
      .filter(Boolean);
    const fallbackName =
      channel.type === 'dm'
        ? memberLabels.join(', ') || '다이렉트 메시지'
        : channel.name || '채널';
    const name =
      channel.name && channel.name.trim().length ? channel.name : fallbackName;
    const desc =
      channel.desc ||
      (channel.type === 'dm' ? '다이렉트 메시지' : (channel.desc || ''));
    const tags = Array.isArray(channel.tags)
      ? channel.tags.filter((tag) => typeof tag === 'string' && tag.trim().length)
      : [];
    return {
      id: channel.id,
      type: channel.type,
      name,
      desc,
      tags,
      locked: !!channel.locked,
      memberCount: memberDetails.length,
      members: memberDetails,
      lastMessageAt: lastMessage?.createdAt || channel.createdAt || null,
      lastMessagePreview: lastMessage ? String(lastMessage.text || '').slice(0, 160) : null,
      createdAt: channel.createdAt || null,
    };
  }

  async function adminListMessageChannelsLocal() {
    const db = await load();
    ensureMessageDefaultsStructure(db);
    const items = (db.messageChannels || [])
      .filter((channel) => channel && channel.id !== 'square')
      .map((channel) => buildAdminChannelEntryLocal(channel, db))
      .filter(Boolean)
      .sort((a, b) => {
        const at = new Date(a.lastMessageAt || a.createdAt || 0).getTime();
        const bt = new Date(b.lastMessageAt || b.createdAt || 0).getTime();
        return bt - at;
      });
    return items;
  }

  async function adminListChannelMessagesLocal(channelId, { limit = 200 } = {}) {
    if (!channelId) throw messageError('channel-required', '채널 ID가 필요합니다.');
    const db = await load();
    ensureMessageDefaultsStructure(db);
    const channel = (db.messageChannels || []).find((entry) => entry && entry.id === channelId);
    if (!channel || channel.id === 'square') {
      throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
    }
    const messages = selectChannelMessages(db, channelId);
    const capped =
      Number.isFinite(limit) && Number(limit) > 0
        ? Math.max(1, Math.min(500, Math.floor(Number(limit))))
        : 200;
    const slice = capped ? messages.slice(-capped) : messages;
    return {
      channel: buildAdminChannelEntryLocal(channel, db),
      messages: slice.map((msg) => mapMessageForClient(msg, db)),
    };
  }

  function buildChannelMeta(channel, db, viewerId, { includeWhenNotJoined = false } = {}) {
    if (!channel) return null;
    const members = Array.isArray(channel.members) ? channel.members : [];
    const users = db.users || {};
    const joined =
      channel.type === 'square'
        ? true
        : channel.type === 'dm'
        ? members.includes(viewerId)
        : channel.type === 'group'
        ? members.includes(viewerId)
        : false;
    if (!joined && !includeWhenNotJoined) return null;

    const messages = selectChannelMessages(db, channel.id);
    const lastMessage = messages.length ? messages[messages.length - 1] : null;
    const counterpartId =
      channel.type === 'dm' ? members.find((memberId) => memberId && memberId !== viewerId) : null;
    const counterpartRaw = counterpartId ? users[counterpartId] : null;
    const counterpart = counterpartRaw ? publicUser(counterpartRaw) : null;
    let displayName = channel.name || '채널';
    let displayDesc = channel.desc || '';
    if (channel.type === 'dm' && counterpart) {
      displayName = counterpart.name || counterpart.handle || displayName;
      displayDesc = counterpart.handle || '다이렉트 메시지';
    }

    const memberCount =
      channel.type === 'square'
        ? Object.keys(users).length
        : Array.isArray(channel.members)
        ? channel.members.length
        : 0;

    return {
      id: channel.id,
      type: channel.type,
      name: displayName,
      desc: displayDesc,
      avatar: channel.avatar || null,
      tags: Array.isArray(channel.tags) ? [...channel.tags] : [],
      memberCount,
      joined,
      locked: !!channel.locked,
      lastMessageAt: lastMessage ? lastMessage.createdAt : channel.createdAt || null,
      lastMessagePreview: lastMessage ? String(lastMessage.text || '').slice(0, 120) : null,
      unreadCount: 0,
      counterpart: counterpart
        ? {
            id: counterpart.id,
            handle: counterpart.handle,
            name: counterpart.name,
            avatarUrl: counterpart.avatarUrl || null,
          }
        : null,
      createdAt: channel.createdAt || null,
    };
  }

  function assertChannelAccess(channel, viewerId) {
    if (!channel) throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
    if (channel.type === 'square') return true;
    const members = Array.isArray(channel.members) ? channel.members : [];
    if (!viewerId) throw messageError('auth-required', '인증이 필요합니다.');
    if (!members.includes(viewerId)) {
      throw messageError('access-denied', '채널에 접근할 수 없습니다.');
    }
    return true;
  }

  async function listMessageChannelsForUser(userId) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const db = await load();
    ensureMessageDefaultsStructure(db);
    const user = db.users?.[userId];
    if (!user) throw messageError('auth-required', '사용자를 찾을 수 없습니다.');
    const joined = [];
    const joinableGroups = [];
    db.messageChannels.forEach((channel) => {
      if (!channel) return;
      const includeWhenNotJoined = channel.type === 'group';
      const meta = buildChannelMeta(channel, db, userId, { includeWhenNotJoined });
      if (!meta) return;
      if (channel.type === 'group' && !meta.joined) {
        joinableGroups.push(meta);
      } else {
        joined.push(meta);
      }
    });
    joined.sort((a, b) => {
      const at = new Date(a.lastMessageAt || a.createdAt || 0).getTime();
      const bt = new Date(b.lastMessageAt || b.createdAt || 0).getTime();
      return bt - at;
    });
    const squareIdx = joined.findIndex((c) => c.id === 'square');
    if (squareIdx > 0) {
      const [square] = joined.splice(squareIdx, 1);
      joined.unshift(square);
    }
    joinableGroups.sort((a, b) => (a.name || '').localeCompare(b.name || '', 'ko'));
    return { channels: joined, groups: joinableGroups };
  }

  async function ensureDirectChannelForUsers(viewerId, targetId) {
    if (!viewerId || !targetId) throw messageError('invalid-input', '대상 정보가 부족합니다.');
    if (viewerId === targetId) {
      throw messageError('invalid-target', '자기 자신과의 다이렉트 메시지는 생성할 수 없습니다.');
    }
    const db = await load();
    ensureMessageDefaultsStructure(db);
    const users = db.users || {};
    if (!users[viewerId]) throw messageError('auth-required', '사용자를 찾을 수 없습니다.');
    if (!users[targetId]) throw messageError('user-not-found', '상대 사용자를 찾을 수 없습니다.');
    const members = [viewerId, targetId].sort();
    const channelId = `dm_${members.join('_')}`;
    let channel = db.messageChannels.find((c) => c && c.id === channelId);
    const nowIso = new Date().toISOString();
    if (!channel) {
      channel = {
        id: channelId,
        type: 'dm',
        name: '',
        desc: '다이렉트 메시지',
        tags: [],
        avatar: null,
        locked: false,
        members,
        createdAt: nowIso,
        createdBy: viewerId,
      };
      db.messageChannels.push(channel);
    } else {
      const existingMembers = Array.isArray(channel.members) ? channel.members : [];
      channel.members = Array.from(new Set([...existingMembers, ...members]));
      if (!channel.createdAt) channel.createdAt = nowIso;
    }
    await save(db);
    return buildChannelMeta(channel, db, viewerId, { includeWhenNotJoined: true });
  }

  async function joinMessageChannel(channelId, userId) {
    if (!channelId) throw messageError('channel-required', '채널 ID가 필요합니다.');
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const db = await load();
    ensureMessageDefaultsStructure(db);
    const channel = db.messageChannels.find((c) => c && c.id === channelId);
    if (!channel) throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
    if (channel.type !== 'group') {
      throw messageError('invalid-channel', '그룹 채널만 참여할 수 있습니다.');
    }
    channel.members ||= [];
    if (!channel.members.includes(userId)) {
      channel.members.push(userId);
      await save(db);
    } else {
      await save(db);
    }
    return buildChannelMeta(channel, db, userId, { includeWhenNotJoined: true });
  }

  async function createGroupChannel({ userId, name, desc, tags }) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const db = await load();
    ensureMessageDefaultsStructure(db);
    const user = db.users?.[userId];
    if (!user) throw messageError('auth-required', '사용자를 찾을 수 없습니다.');
    let normalizedName;
    try {
      normalizedName = normalizeGroupName(name);
    } catch (err) {
      throw messageError(err.code || 'invalid-name', err.message || '그룹 이름을 확인해 주세요.');
    }
    const normalizedDesc = normalizeGroupDesc(desc);
    const normalizedTags = normalizeGroupTags(tags);
    const lower = normalizedName.toLowerCase();
    const duplicate = db.messageChannels.find(
      (channel) =>
        channel &&
        channel.type === 'group' &&
        String(channel.name || '').trim().toLowerCase() === lower,
    );
    if (duplicate) {
      throw messageError('duplicate-name', '이미 사용 중인 그룹 이름입니다.');
    }
    const groupId = 'grp_' + uid(6);
    const nowIso = new Date().toISOString();
    const group = {
      id: groupId,
      type: 'group',
      name: normalizedName,
      desc: normalizedDesc,
      tags: normalizedTags,
      avatar: null,
      locked: false,
      createdAt: nowIso,
      createdBy: userId,
      members: [userId],
    };
    db.messageChannels.push(group);
    await save(db);
    return buildChannelMeta(group, db, userId, { includeWhenNotJoined: true });
  }

  async function leaveGroupChannel(channelId, userId) {
    if (!channelId) throw messageError('channel-required', '채널 ID가 필요합니다.');
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const db = await load();
    ensureMessageDefaultsStructure(db);
    ensureUserFollowStructure(db);
    const channel = db.messageChannels.find((c) => c && c.id === channelId);
    if (!channel) throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
    if (channel.type !== 'group') {
      throw messageError('invalid-channel', '그룹 채널만 나갈 수 있습니다.');
    }
    channel.members ||= [];
    if (!channel.members.includes(userId)) {
      throw messageError('not-member', '참여 중인 그룹이 아닙니다.');
    }
    channel.members = channel.members.filter((memberId) => memberId !== userId);
    await save(db);
    return true;
  }

  async function followUserRecord(followerId, targetId) {
    if (!followerId || !targetId) throw messageError('invalid-input', '대상 정보가 부족합니다.');
    if (followerId === targetId) throw messageError('invalid-target', '자기 자신을 팔로우할 수 없습니다.');
    const db = await load();
    ensureUserFollowStructure(db);
    const follower = db.users?.[followerId];
    const target = db.users?.[targetId];
    if (!follower || !target) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    const alreadyFollowing = isFollowingLocal(db, followerId, targetId);
    if (!alreadyFollowing) {
      db.userFollows.push({ followerId, targetId, createdAt: new Date().toISOString() });
      appendNotificationLocal(db, uid, {
        userId: targetId,
        type: 'follow',
        actorId: followerId,
        payload: null,
      });
      await save(db);
    }
    return getUserProfileView({ userId: targetId, viewerId: followerId, limit: 0 });
  }

  async function unfollowUserRecord(followerId, targetId) {
    if (!followerId || !targetId) throw messageError('invalid-input', '대상 정보가 부족합니다.');
    if (followerId === targetId) throw messageError('invalid-target', '자기 자신을 팔로우할 수 없습니다.');
    const db = await load();
    ensureUserFollowStructure(db);
    const follower = db.users?.[followerId];
    const target = db.users?.[targetId];
    if (!follower || !target) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    if (isFollowingLocal(db, followerId, targetId)) {
      db.userFollows = db.userFollows.filter((entry) => !(entry.followerId === followerId && entry.targetId === targetId));
      await save(db);
    }
    return getUserProfileView({ userId: targetId, viewerId: followerId, limit: 0 });
  }

  async function getUserProfileView({ handle, userId, viewerId, limit = 20 }) {
    const db = await load();
    ensureMessageDefaultsStructure(db);
    ensureUserFollowStructure(db);
    let user = null;
    if (userId) {
      user = db.users?.[userId] || null;
    }
    if (!user && handle) {
      const normalizedHandle = String(handle || '').trim().toLowerCase();
      if (normalizedHandle) {
        user = Object.values(db.users || {}).find((candidate) => (candidate?.handle || '').toLowerCase() === normalizedHandle) || null;
      }
    }
    if (!user) return null;

    const viewer = viewerId ? db.users?.[viewerId] || null : null;
    const postsAll = (db.posts || [])
      .filter((post) => post && post.author && post.author.id === user.id)
      .filter((post) => (post.status || 'active') !== 'removed')
      .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    const normalizedPosts = postsAll.map((post) => {
      const author = post.author?.id ? db.users?.[post.author.id] : null;
      const comments = (post.comments || []).map((comment) => {
        const commentUser = comment?.author?.id ? db.users?.[comment.author.id] : null;
        if (commentUser) {
          return { ...comment, author: compactAuthor(commentUser) };
        }
        return { ...comment };
      });
      return {
        ...post,
        author: author ? compactAuthor(author) : (post.author ? { ...post.author } : null),
        attachments: (post.attachments || []).map((att) => normalizeAttachmentForStore(att)).filter(Boolean),
        comments,
      };
    });
    const limitedPosts = limit > 0 ? normalizedPosts.slice(0, Math.max(0, limit)) : normalizedPosts;
    const posts = limitedPosts.map((post) => toClientPost(post, { userId: viewerId || null }));
    const followStats = computeFollowStatsLocal(db, user.id);

    return {
      user: publicUser(user),
      stats: {
        followers: followStats.followers,
        following: followStats.following,
        posts: postsAll.length,
      },
      isFollowing: viewerId ? isFollowingLocal(db, viewerId, user.id) : false,
      posts,
      viewer: viewer ? publicUser(viewer) : null,
    };
  }

  async function getUserProfileRecord(userId) {
    if (!userId) return null;
    const db = await load();
    const user = db.users?.[userId];
    if (!user) return null;
    return publicUser(user);
  }

  async function updateUserProfileRecord(userId, updates = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const db = await load();
    const user = db.users?.[userId];
    if (!user) throw messageError('auth-required', '사용자를 찾을 수 없습니다.');
    if (updates.name !== undefined) {
      user.name = String(updates.name || '').trim();
    }
    if (updates.handle !== undefined) {
      user.handle = updates.handle || null;
    }
    if (updates.email !== undefined) {
      user.email = updates.email || null;
    }
    if (updates.phone !== undefined) {
      user.phone = updates.phone || null;
    }
    if (updates.avatarUrl !== undefined) {
      user.avatarUrl = updates.avatarUrl;
    }
    if (updates.updatedAt !== undefined) {
      user.updatedAt = updates.updatedAt;
    } else {
      user.updatedAt = new Date().toISOString();
    }
    db.users[userId] = user;
    await save(db);
    return publicUser(user);
  }

  async function getUserAuthRecord(userId) {
    if (!userId) return null;
    const db = await load();
    const user = db.users?.[userId];
    if (!user) return null;
    return {
      id: user.id,
      handle: user.handle || null,
      passwordHash: user.passwordHash || null,
      email: user.email || null,
      phone: user.phone || null,
    };
  }

  async function updateUserPasswordRecord(userId, newPasswordHash) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    if (!newPasswordHash) throw messageError('invalid-input', '비밀번호가 필요합니다.');
    const db = await load();
    const user = db.users?.[userId];
    if (!user) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    user.passwordHash = newPasswordHash;
    user.updatedAt = new Date().toISOString();
    db.users[userId] = user;
    await save(db);
    return true;
  }

  async function listChannelMessages(channelId, { userId, limit = 50, after } = {}) {
    if (!channelId) throw messageError('channel-required', '채널 ID가 필요합니다.');
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const db = await load();
    ensureMessageDefaultsStructure(db);
    const channel = db.messageChannels.find((c) => c && c.id === channelId);
    assertChannelAccess(channel, userId);
    const messages = selectChannelMessages(db, channelId);
    let filtered = messages;
    let afterTs = null;
    if (after) {
      const parsed = Date.parse(after);
      if (Number.isFinite(parsed)) {
        afterTs = parsed;
        filtered = messages.filter((msg) => Date.parse(msg.createdAt || 0) > parsed);
      }
    }
    let slice = filtered;
    if (typeof limit === 'number' && Number.isFinite(limit) && limit > 0) {
      const cap = Math.max(1, Math.floor(limit));
      slice = filtered.slice(-cap);
    }
    return {
      channel: buildChannelMeta(channel, db, userId, { includeWhenNotJoined: true }),
      messages: slice.map((msg) => mapMessageForClient(msg, db)),
    };
  }

  async function appendChannelMessage(channelId, { user, text }) {
    if (!channelId) throw messageError('channel-required', '채널 ID가 필요합니다.');
    if (!user || !user.id) throw messageError('auth-required', '인증이 필요합니다.');
    const body = String(text || '').trim();
    if (!body) throw messageError('text-required', '메시지 내용을 입력해 주세요.');
    const db = await load();
    ensureMessageDefaultsStructure(db);
    const channel = db.messageChannels.find((c) => c && c.id === channelId);
    assertChannelAccess(channel, user.id);
    const message = {
      id: 'msg_' + uid(8),
      channelId,
      authorId: user.id,
      text: body.slice(0, 2000),
      createdAt: new Date().toISOString(),
    };
    db.messageMessages.push(message);
    await save(db);
    return mapMessageForClient(message, db);
  }

  async function invalidateUserSessions(userId) {
    if (!userId) return;
    const db = await load();
    let changed = false;
    Object.entries(db.sessions || {}).forEach(([sid, uidStored]) => {
      if (uidStored === userId) {
        delete db.sessions[sid];
        changed = true;
      }
    });
    if (changed) await save(db);
  }

  async function listAccountActions(userId) {
    if (!userId) return [];
    const db = await load();
    ensureUserAccountDefaults(db);
    return (db.userActions || [])
      .filter((entry) => entry && entry.userId === userId)
      .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
      .map((entry) => {
        const actor = entry.actorId ? db.users?.[entry.actorId] : null;
        return {
          id: entry.id,
          action: entry.action,
          reason: entry.reason || null,
          detail: entry.detail || null,
          actor: actor
            ? {
                id: actor.id,
                handle: actor.handle || null,
                name: actor.name || null,
              }
            : null,
          actorType: entry.actorType || null,
          createdAt: entry.createdAt || null,
          metadata: entry.metadata || null,
        };
      });
    }

  async function deactivateAccount(userId, { reason, actorId, actorType } = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const db = await load();
    ensureUserAccountDefaults(db);
    const user = db.users?.[userId];
    if (!user) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    if (user.status === 'deleted') throw messageError('account-deleted', '이미 삭제된 계정입니다.');
    if (user.status === 'deactivated') throw messageError('account-already-deactivated', '이미 비활성화된 계정입니다.');
    if (user.status === 'suspended') throw messageError('account-suspended', '정지된 계정입니다.');
    user.status = 'deactivated';
    user.deactivatedAt = new Date().toISOString();
    db.users[userId] = user;
    recordUserActionLocal(db, uid, {
      userId,
      action: 'deactivated',
      reason: reason || null,
      actorId: actorId || userId,
      actorType: actorType || 'self',
    });
    await save(db);
    await invalidateUserSessions(userId);
    return publicUser(user);
  }

  async function deleteAccount(userId, { reason, detail, actorId, actorType } = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const db = await load();
    ensureUserAccountDefaults(db);
    const user = db.users?.[userId];
    if (!user) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    if (user.status === 'deleted') throw messageError('account-deleted', '이미 삭제된 계정입니다.');
    user.status = 'deleted';
    user.deletedAt = new Date().toISOString();
    user.deactivatedAt = user.deactivatedAt || user.deletedAt;
    user.email = null;
    user.phone = null;
    user.avatarUrl = null;
    user.suspendedUntil = null;
    db.users[userId] = user;
    const contentStats = purgeUserContentLocal(db, userId);
    recordUserActionLocal(db, uid, {
      userId,
      action: 'deleted',
      reason: reason || null,
      detail: detail || null,
      actorId: actorId || userId,
      actorType: actorType || 'self',
      metadata: {
        postsRemoved: contentStats.postsRemoved,
        commentsRemoved: contentStats.commentsRemoved,
      },
    });
    await save(db);
    await invalidateUserSessions(userId);
    return publicUser(user);
  }

  function parseUntilDate(until) {
    if (!until) return null;
    const date = new Date(until);
    const time = date.getTime();
    if (!Number.isFinite(time)) return null;
    return date.toISOString();
  }

  async function suspendAccount(userId, { reason, detail, until, actorId, actorType } = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const db = await load();
    ensureUserAccountDefaults(db);
    const user = db.users?.[userId];
    if (!user) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    if (user.status === 'deleted') throw messageError('account-deleted', '이미 삭제된 계정입니다.');
    if (user.status === 'suspended') throw messageError('account-already-suspended', '이미 정지된 계정입니다.');
    if (user.status === 'banned') throw messageError('account-banned', '영구 정지된 계정입니다.');
    const untilIso = parseUntilDate(until);
    user.status = 'suspended';
    user.suspendedUntil = untilIso;
    user.deactivatedAt = user.deactivatedAt || new Date().toISOString();
    db.users[userId] = user;
    recordUserActionLocal(db, uid, {
      userId,
      action: 'suspension',
      reason: reason || null,
      detail: detail || null,
      actorId: actorId || null,
      actorType: actorType || (actorId ? 'user' : 'system'),
      metadata: untilIso ? { until: untilIso } : null,
    });
    await save(db);
    await invalidateUserSessions(userId);
    return publicUser(user);
  }

  async function banAccount(userId, { reason, detail, actorId, actorType } = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const db = await load();
    ensureUserAccountDefaults(db);
    const user = db.users?.[userId];
    if (!user) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    if (user.status === 'deleted') throw messageError('account-deleted', '이미 삭제된 계정입니다.');
    if (user.status === 'banned') throw messageError('account-banned', '이미 영구 정지된 계정입니다.');
    user.status = 'banned';
    user.suspendedUntil = null;
    user.deactivatedAt = user.deactivatedAt || new Date().toISOString();
    db.users[userId] = user;
    recordUserActionLocal(db, uid, {
      userId,
      action: 'banned',
      reason: reason || null,
      detail: detail || null,
      actorId: actorId || null,
      actorType: actorType || (actorId ? 'user' : 'system'),
    });
    await save(db);
    await invalidateUserSessions(userId);
    return publicUser(user);
  }

  async function restoreAccount(userId, { reason, detail, actorId, actorType } = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const db = await load();
    ensureUserAccountDefaults(db);
    const user = db.users?.[userId];
    if (!user) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    if (user.status === 'deleted') throw messageError('account-deleted', '이미 삭제된 계정입니다.');
    if (user.status !== 'deactivated' && user.status !== 'suspended' && user.status !== 'banned') {
      throw messageError('account-active', '조치 상태의 계정이 아닙니다.');
    }
    user.status = 'active';
    user.deactivatedAt = null;
    user.suspendedUntil = null;
    db.users[userId] = user;
    recordUserActionLocal(db, uid, {
      userId,
      action: 'restored',
      reason: reason || null,
      detail: detail || null,
      actorId: actorId || null,
      actorType: actorType || (actorId ? 'user' : 'system'),
    });
    await save(db);
    return publicUser(user);
  }

  function presentUserForAdmin(user) {
    if (!user) return null;
    return {
      id: user.id,
      handle: user.handle || null,
      name: user.name || null,
      email: user.email || null,
      role: user.role || 'user',
      status: user.status || 'active',
      createdAt: user.createdAt || null,
      suspendedUntil: user.suspendedUntil || null,
      isSuperAdmin: !!user.isSuperAdmin,
    };
  }

  async function adminListReports({ query, type, status, limit = 100 } = {}) {
    const db = await load();
    ensureReportsStructure(db);
    const lowerQuery = query ? String(query).toLowerCase() : '';
    let items = (db.reports || []).map((report) => buildReportForAdmin(report, db));
    if (type) {
      const t = String(type).toLowerCase();
      items = items.filter((item) => (item.type || '').toLowerCase() === t);
    }
    if (status) {
      const s = String(status).toLowerCase();
      items = items.filter((item) => (item.status || '').toLowerCase() === s);
    }
    if (lowerQuery) {
      items = items.filter((item) => {
        const haystack = [
          item.summary || '',
          item.reason || '',
          item.detail || '',
          item.reporter?.handle || '',
          item.reporter?.name || '',
          item.target?.handle || '',
          item.target?.name || '',
        ]
          .join(' ')
          .toLowerCase();
        return haystack.includes(lowerQuery);
      });
    }
    items.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    const max = Math.min(Math.max(limit || 0, 0), 500);
    return max ? items.slice(0, max) : items;
  }

  async function adminResolveReport(reportId, status = 'closed') {
    if (!reportId) return false;
    const db = await load();
    ensureReportsStructure(db);
    const report = (db.reports || []).find((entry) => entry && entry.id === reportId);
    if (!report) return false;
    report.status = status;
    report.updatedAt = new Date().toISOString();
    await save(db);
    return true;
  }

  async function adminListUsers({ query, role, status, limit = 100 } = {}) {
    const db = await load();
    ensureUserAccountDefaults(db);
    const lowerQuery = query ? String(query).toLowerCase() : '';
    let items = Object.values(db.users || {}).map((user) => presentUserForAdmin(user));
    if (role) {
      const r = String(role).toLowerCase();
      items = items.filter((user) => {
        const userRole = (user.role || 'user').toLowerCase();
        return r === 'user' ? userRole === 'user' : userRole === r;
      });
    }
    if (status) {
      const s = String(status).toLowerCase();
      items = items.filter((user) => (user.status || '').toLowerCase() === s);
    }
    if (lowerQuery) {
      items = items.filter((user) => {
        const fields = [user.handle, user.name, user.email, user.id]
          .filter(Boolean)
          .map((val) => String(val).toLowerCase());
        return fields.some((field) => field.includes(lowerQuery));
      });
    }
    items.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    const max = Math.min(Math.max(limit || 0, 0), 500);
    return max ? items.slice(0, max) : items;
  }

  async function adminListPosts({ query, status, limit = 100 } = {}) {
    const db = await load();
    ensureReportsStructure(db);
    const lowerQuery = query ? String(query).toLowerCase() : '';
    const reports = (db.reports || []).filter((report) => (report.status || 'open') === 'open' && report.postId);
    const reportedPostIds = new Set(reports.map((report) => report.postId));
    const posts = Array.isArray(db.posts) ? db.posts.slice() : [];
    let items = posts
      .map((post) => {
        const authorUser = post.author?.id ? db.users?.[post.author.id] : null;
        const derivedStatus = (post.status && post.status !== 'active')
          ? post.status
          : (reportedPostIds.has(post.id) ? 'reported' : 'active');
        return {
          id: post.id,
          text: post.text || '',
          createdAt: post.createdAt || null,
          status: derivedStatus,
          author: {
            id: post.author?.id || authorUser?.id || null,
            handle: post.author?.handle || authorUser?.handle || null,
            name: post.author?.name || authorUser?.name || null,
          },
        };
      })
      .filter((item) => item);
    if (status) {
      const s = String(status).toLowerCase();
      items = items.filter((item) => (item.status || '').toLowerCase() === s);
    }
    if (lowerQuery) {
      items = items.filter((item) => {
        const fields = [item.text, item.author?.handle, item.author?.name]
          .filter(Boolean)
          .map((val) => String(val).toLowerCase());
        return fields.some((field) => field.includes(lowerQuery));
      });
    }
    items.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    const max = Math.min(Math.max(limit || 0, 0), 500);
    return max ? items.slice(0, max) : items;
  }

  async function setUserRoleLocal(userId, role) {
    if (!userId) throw Object.assign(new Error('user-not-found'), { code: 'user-not-found' });
    const db = await load();
    ensureUserAccountDefaults(db);
    const user = db.users?.[userId];
    if (!user) throw Object.assign(new Error('user-not-found'), { code: 'user-not-found' });
    const normalized = role ? String(role).toLowerCase() : 'user';
    user.role = normalized === 'superadmin' ? 'superadmin' : normalized === 'admin' ? 'admin' : 'user';
    user.isSuperAdmin = user.role === 'superadmin';
    await save(db);
    return presentUserForAdmin(user);
  }

  async function logUserActionLocal({ userId, action, reason, detail, actorId, actorType, metadata }) {
    if (!userId || !action) return;
    const db = await load();
    ensureUserAccountDefaults(db);
    recordUserActionLocal(db, uid, {
      userId,
      action,
      reason: reason || null,
      detail: detail || null,
      actorId: actorId || null,
      actorType: actorType || (actorId ? 'user' : 'system'),
      metadata: metadata || null,
    });
    await save(db);
  }

  return {
    mode: 'file',
    ensureReady,
    async getConfig() {
      const db = await load();
      ensureSystemConfig(db);
      return presentSystemConfig(db.config);
    },
    async updateConfig(partial) {
      const db = await load();
      ensureSystemConfig(db);
      if (typeof partial.allowAnon === 'boolean') {
        db.config.allowAnon = partial.allowAnon;
      }
      if (typeof partial.basicPostingRestricted === 'boolean') {
        db.config.basicPostingRestricted = partial.basicPostingRestricted;
      }
      if (typeof partial.registrationMode === 'string') {
        const mode = partial.registrationMode === 'invite' ? 'invite' : 'open';
        db.config.registrationMode = mode;
      }
      if (typeof partial.requiresReferralCode === 'boolean') {
        db.config.registrationMode = partial.requiresReferralCode ? 'invite' : 'open';
      }
      await save(db);
      return presentSystemConfig(db.config);
    },
    async listAnnouncements(opts) {
      return listAnnouncementsLocal(opts || {});
    },
    async getAnnouncement(id) {
      return getAnnouncementLocal(id);
    },
    async createAnnouncement(payload) {
      return createAnnouncementLocal(payload || {});
    },
    async updateAnnouncement(id, payload) {
      return updateAnnouncementLocal(id, payload || {});
    },
    async deleteAnnouncement(id) {
      return deleteAnnouncementLocal(id);
    },
    async listReferralCodes() {
      return listReferralCodesLocal();
    },
    async createReferralCode(payload) {
      return createReferralCodeLocal(payload || {});
    },
    async revokeReferralCode(code) {
      return revokeReferralCodeLocal(code);
    },
    async verifyReferralCode(code) {
      return verifyReferralCodeLocal(code);
    },
    async consumeReferralCode(code, meta) {
      return consumeReferralCodeLocal(code, meta || {});
    },
    async adminListReports(opts) {
      return adminListReports(opts || {});
    },
    async adminResolveReport(id, status) {
      return adminResolveReport(id, status || 'closed');
    },
    async adminListUsers(opts) {
      return adminListUsers(opts || {});
    },
    async adminListPosts(opts) {
      return adminListPosts(opts || {});
    },
    async setUserRole(userId, role) {
      return setUserRoleLocal(userId, role);
    },
    async logUserAction(entry) {
      return logUserActionLocal(entry || {});
    },
    async getSessionUser(sid) {
      if (!sid) return null;
      const db = await load();
      const userId = db.sessions[sid];
      const user = db.users?.[userId];
      if (!user) return null;
      if (['deleted', 'deactivated', 'suspended', 'banned'].includes(user.status)) return null;
      return publicUser(user);
    },
    async createSession(userId) {
      const db = await load();
      const user = db.users?.[userId];
      if (!user) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
      if (user.status === 'deleted') throw messageError('account-deleted', '삭제된 계정입니다.');
      if (user.status === 'deactivated') throw messageError('account-deactivated', '비활성화된 계정입니다.');
      if (user.status === 'suspended') throw messageError('account-suspended', '정지된 계정입니다.');
      if (user.status === 'banned') throw messageError('account-banned', '영구 정지된 계정입니다.');
      const sid = uid(16);
      db.sessions[sid] = userId;
      await save(db);
      return sid;
    },
    async deleteSession(sid) {
      if (!sid) return;
      const db = await load();
      if (db.sessions[sid]) {
        delete db.sessions[sid];
        await save(db);
      }
    },
    async getUserProfile(userId) {
      return getUserProfileRecord(userId);
    },
    async updateUserProfile(userId, updates) {
      return updateUserProfileRecord(userId, updates);
    },
    async getUserAuth(userId) {
      return getUserAuthRecord(userId);
    },
    async updateUserPassword(userId, newPasswordHash) {
      return updateUserPasswordRecord(userId, newPasswordHash);
    },
    async getUserProfileView(opts) {
      return getUserProfileView(opts || {});
    },
    async listFollowers(userId, opts) {
      return listFollowersLocal(userId, opts || {});
    },
    async listFollowing(userId, opts) {
      return listFollowingLocal(userId, opts || {});
    },
    async searchUsers(opts) {
      return searchUsersLocal(opts || {});
    },
    async listRandomUsers(opts) {
      return listRandomUsersLocal(opts || {});
    },
    async searchPosts(opts) {
      return searchPostsLocal(opts || {});
    },
    async searchTags(opts) {
      return searchTagsLocal(opts || {});
    },
    async getTrendingTags(opts) {
      return getTrendingTagsLocal(opts || {});
    },
    async listNotifications(userId, opts = {}) {
      if (!userId) return [];
      const { type = 'all', limit = 20, markSeen = true } = opts || {};
      const db = await load();
      ensureNotificationStructure(db);
      const normalizedType = typeof type === 'string' ? type : 'all';
      const max = Math.min(Math.max(Number(limit) || 0, 1), 100);
      const notifications = (db.notifications || [])
        .filter(
          (entry) =>
            entry &&
            entry.userId === userId &&
            (normalizedType === 'all' || entry.type === normalizedType),
        )
        .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
        .slice(0, max);
      let changed = false;
      if (markSeen) {
        const nowIso = new Date().toISOString();
        notifications.forEach((entry) => {
          if (!entry.seenAt) {
            entry.seenAt = nowIso;
            changed = true;
          }
        });
      }
      if (changed) {
        await save(db);
      }
      return notifications.map((entry) => ({
        id: entry.id,
        type: entry.type,
        createdAt: entry.createdAt,
        seenAt: entry.seenAt || null,
        actor: entry.actorId ? compactAuthor(db.users?.[entry.actorId]) : null,
        postId: entry.postId || null,
        commentId: entry.commentId || null,
        payload: entry.payload || null,
      }));
    },
    async countUnreadNotifications(userId) {
      if (!userId) return 0;
      const db = await load();
      ensureNotificationStructure(db);
      return (db.notifications || []).filter(
        (entry) => entry && entry.userId === userId && !entry.seenAt,
      ).length;
    },
    async adminListMessageChannels() {
      return adminListMessageChannelsLocal();
    },
    async adminListChannelMessages(channelId, opts) {
      return adminListChannelMessagesLocal(channelId, opts || {});
    },
    async listAccountActions(userId) {
      return listAccountActions(userId);
    },
    async getLatestAccountAction(userId) {
      return getLatestAccountActionLocal(userId);
    },
    async deactivateAccount(userId, payload) {
      return deactivateAccount(userId, payload || {});
    },
    async deleteAccount(userId, payload) {
      return deleteAccount(userId, payload || {});
    },
    async suspendAccount(userId, payload) {
      return suspendAccount(userId, payload || {});
    },
    async banAccount(userId, payload) {
      return banAccount(userId, payload || {});
    },
    async restoreAccount(userId, payload) {
      return restoreAccount(userId, payload || {});
    },
    async invalidateUserSessions(userId) {
      return invalidateUserSessions(userId);
    },
    async followUser(followerId, targetId) {
      return followUserRecord(followerId, targetId);
    },
    async unfollowUser(followerId, targetId) {
      return unfollowUserRecord(followerId, targetId);
    },
    async findUserByHandle(handle) {
      if (!handle) return null;
      const db = await load();
      let normalized = String(handle || '').trim().toLowerCase();
      if (!normalized) return null;
      if (!normalized.startsWith('@')) normalized = '@' + normalized;
      const direct =
        Object.values(db.users || {}).find(
          (u) => (u.handle || '').toLowerCase() === normalized,
        ) || null;
      if (direct) return direct;
      const fallback =
        Object.values(db.users || {}).find(
          (u) => (u.handle || '').toLowerCase() === normalized.slice(1),
        ) || null;
      return fallback;
    },
    async findUserByEmail(email) {
      if (!email) return null;
      const db = await load();
      const target = String(email).toLowerCase();
      return (
        Object.values(db.users || {}).find(
          (u) => (u.email || '').toLowerCase() === target,
        ) || null
      );
    },
    async findUserByPhone(phone) {
      if (!phone) return null;
      const db = await load();
      const target = String(phone);
      return (
        Object.values(db.users || {}).find(
          (u) => (u.phone || '') === target,
        ) || null
      );
    },
    async createUser({ email, phone, passwordHash, handle, name, avatarUrl }) {
      const db = await load();
      const id = 'u_' + uid(8);
      const user = {
        id,
        email,
        phone,
        handle,
        name,
        passwordHash,
        avatarUrl: avatarUrl || null,
        createdAt: new Date().toISOString(),
        status: 'active',
        deactivatedAt: null,
        deletedAt: null,
        suspendedUntil: null,
      };
      db.users[id] = user;
      await save(db);
      return user;
    },
    async getPostById(postId) {
      if (!postId) return null;
      const db = await load();
      const post = (db.posts || []).find((p) => p.id === postId);
      if (!post) return null;
      return {
        ...post,
        attachments: (post.attachments || [])
          .map((att) => normalizeAttachmentForStore(att))
          .filter(Boolean),
        comments: (post.comments || []).map((c) => ({ ...c })),
      };
    },
    async listPosts() {
      const db = await load();
      return db.posts
        .slice()
        .filter((post) => (post.status || 'active') !== 'removed')
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .map((post) => {
          const baseAuthor = post.author?.id ? db.users?.[post.author.id] : null;
          const author = baseAuthor ? compactAuthor(baseAuthor) : (post.author ? { ...post.author } : null);
          const comments = (post.comments || [])
            .slice()
            .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
            .map((comment) => {
              const commentAuthorUser = comment?.author?.id ? db.users?.[comment.author.id] : null;
              if (commentAuthorUser) {
                return {
                  ...comment,
                  author: compactAuthor(commentAuthorUser),
                };
              }
              return { ...comment };
            });
          return {
            ...post,
            author,
            attachments: (post.attachments || [])
              .map((att) => normalizeAttachmentForStore(att))
              .filter(Boolean),
            comments,
            status: post.status || 'active',
          };
        });
    },
    async createPost({ user, text, attachments }) {
      const db = await load();
      const nowIso = new Date().toISOString();
      const normalizedAttachments = Array.isArray(attachments)
        ? attachments.map((att) => normalizeAttachmentForStore(att)).filter(Boolean)
        : [];
      const post = {
        id: 'p_' + uid(6),
        author: {
          id: user.id,
          handle: user.handle,
          name: user.name,
          avatarUrl: user.avatarUrl || null,
        },
        text: String(text || '').slice(0, 2000),
        createdAt: nowIso,
        attachments: normalizedAttachments,
        comments: [],
        status: 'active',
      };
      db.posts.push(post);
      await save(db);
      return post;
    },
    async updatePost(postId, { text, attachments }) {
      if (!postId) return null;
      const db = await load();
      const post = db.posts.find((p) => p.id === postId);
      if (!post) return null;
      if (typeof text === 'string') {
        post.text = String(text).slice(0, 2000);
      }
      if (Array.isArray(attachments)) {
        post.attachments = attachments
          .map((att) => normalizeAttachmentForStore(att))
          .filter(Boolean);
      }
      await save(db);
      return post;
    },
    async deletePost(postId) {
      if (!postId) return false;
      const db = await load();
      const post = db.posts.find((p) => p.id === postId);
      if (!post) return false;
      post.status = 'removed';
      post.removedAt = new Date().toISOString();
      await save(db);
      return true;
    },
    async createComment({ postId, payload }) {
      const db = await load();
      const post = db.posts.find((p) => p.id === postId);
      if (!post) return null;
      const comment = {
        id: 'c_' + uid(6),
        postId,
        text: String(payload.text || '').slice(0, 1000),
        createdAt: new Date().toISOString(),
        authorType: payload.authorType,
      };
    if (payload.authorType === 'user') {
      comment.author = {
        id: payload.user.id,
        handle: payload.user.handle,
        name: payload.user.name,
        avatarUrl: payload.user.avatarUrl || null,
      };
    } else if (payload.authorType === 'guest') {
      comment.guestPwHash = payload.guestPwHash;
    }
    post.comments.push(comment);
    if (
      payload.authorType === 'user' &&
      post.author &&
      post.author.id &&
      post.author.id !== payload.user.id
    ) {
      appendNotificationLocal(db, uid, {
        userId: post.author.id,
        type: 'comment',
        actorId: payload.user.id,
        postId,
        commentId: comment.id,
        payload: {
          text: comment.text,
        },
      });
    }
    await save(db);
    return comment;
  },
    async getCommentById(commentId) {
      const db = await load();
      for (const post of db.posts) {
        const comment = (post.comments || []).find((c) => c.id === commentId);
        if (comment) {
          return { post, comment };
        }
      }
      return null;
    },
    async updateComment(commentId, { text }) {
      const db = await load();
      for (const post of db.posts) {
        const comment = (post.comments || []).find((c) => c.id === commentId);
        if (comment) {
          comment.text = String(text || '').slice(0, 1000);
          await save(db);
          return comment;
        }
      }
      return null;
    },
    async deleteComment(commentId) {
      const db = await load();
      for (const post of db.posts) {
        const idx = (post.comments || []).findIndex((c) => c.id === commentId);
        if (idx >= 0) {
          post.comments.splice(idx, 1);
          await save(db);
          return true;
        }
      }
      return false;
    },
    async getClient(cid) {
      if (!cid) return null;
      const db = await load();
      return db.clients[cid] || null;
    },
    async markClientGuestUsed(cid) {
      if (!cid) return;
      const db = await load();
      db.clients[cid] = { guestUsed: true, usedAt: new Date().toISOString() };
      await save(db);
    },
    async voteOnPoll({ postId, pollId, optionId, userId, cid }) {
      if (!postId) throw Object.assign(new Error('postId required'), { code: 'post-required' });
      if (!pollId) throw Object.assign(new Error('pollId required'), { code: 'poll-required' });
      if (!optionId) throw Object.assign(new Error('optionId required'), { code: 'option-required' });
      const db = await load();
      const post = db.posts.find((p) => p.id === postId);
      if (!post) throw Object.assign(new Error('post not found'), { code: 'post-not-found' });
      const poll = (post.attachments || []).find(
        (att) => att && att.type === 'poll' && att.pollId === pollId,
      );
      if (!poll) throw Object.assign(new Error('poll not found'), { code: 'poll-not-found' });
      if (!poll.voters || typeof poll.voters !== 'object') {
        poll.voters = { users: {}, clients: {} };
      } else {
        poll.voters.users ||= {};
        poll.voters.clients ||= {};
      }
      const identity = userId
        ? { type: 'user', key: userId }
        : cid
        ? { type: 'client', key: cid }
        : null;
      if (!identity) throw Object.assign(new Error('identity required'), { code: 'identity-required' });
      const voterMap = identity.type === 'user' ? poll.voters.users : poll.voters.clients;
      if (voterMap[identity.key]) {
        throw Object.assign(new Error('already voted'), { code: 'already-voted' });
      }
      const option = (poll.options || []).find((opt) => opt.id === optionId);
      if (!option) throw Object.assign(new Error('option not found'), { code: 'option-not-found' });
      option.count = (Number(option.count) || 0) + 1;
      poll.totalVotes = (Number(poll.totalVotes) || 0) + 1;
      voterMap[identity.key] = optionId;
      await save(db);
      return { post, poll };
    },
    async createReport({ postId, reason, detail, reporter }) {
      if (!postId) throw Object.assign(new Error('postId required'), { code: 'post-required' });
      if (!reason) throw Object.assign(new Error('reason required'), { code: 'reason-required' });
      const db = await load();
      const post = db.posts.find((p) => p.id === postId);
      if (!post) throw Object.assign(new Error('post not found'), { code: 'post-not-found' });
      if (!reporter || reporter.type !== 'user' || !reporter.user) {
        throw Object.assign(new Error('reporter invalid'), { code: 'reporter-required' });
      }
      const targetAuthor = post.author || null;
      const nowIso = new Date().toISOString();
      const report = {
        id: 'rpt_' + uid(8),
        type: 'post',
        status: 'open',
        postId,
        summary: String(post.text || '').slice(0, 160),
        reason: String(reason).trim(),
        detail: detail ? String(detail).trim() : null,
        reporter: {
          type: 'user',
          userId: reporter.user.id,
          handle: reporter.user.handle || null,
          name: reporter.user.name || null,
        },
        target: {
          type: 'post',
          id: postId,
          userId: targetAuthor?.id || null,
          handle: targetAuthor?.handle || null,
          name: targetAuthor?.name || null,
        },
        createdAt: nowIso,
        updatedAt: nowIso,
      };
      db.reports ||= [];
      db.reports.push(report);
      await save(db);
      return report;
    },
    async listReports() {
      const db = await load();
      return (db.reports || [])
        .slice()
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .map((report) => ({ ...report }));
    },
    async listMessageChannels(userId) {
      return listMessageChannelsForUser(userId);
    },
    async ensureDirectChannel({ viewerId, targetId }) {
      return ensureDirectChannelForUsers(viewerId, targetId);
    },
    async joinMessageChannel(channelId, userId) {
      return joinMessageChannel(channelId, userId);
    },
    async createMessageGroup({ userId, name, desc, tags }) {
      return createGroupChannel({ userId, name, desc, tags });
    },
    async leaveMessageChannel(channelId, userId) {
      return leaveGroupChannel(channelId, userId);
    },
    async listChannelMessages(channelId, opts) {
      return listChannelMessages(channelId, opts);
    },
    async appendChannelMessage(channelId, opts) {
      return appendChannelMessage(channelId, opts);
    },
    presentPost(post, viewer) {
      return toClientPost(post, viewer);
    },
    async upsertDefaultUser({ id, handle, name, passwordHash }) {
      const db = await load();
      const existing = Object.values(db.users).find((u) => u.handle === handle);
      if (!existing) {
        db.users[id] = {
          id,
          handle,
          name,
          email: 'owner@looma.local',
          phone: '010-0000-0000',
          avatarUrl: null,
          passwordHash,
          createdAt: new Date().toISOString(),
        };
      } else {
        existing.passwordHash ||= passwordHash;
        existing.email ||= 'owner@looma.local';
        existing.phone ||= '010-0000-0000';
        existing.createdAt ||= new Date().toISOString();
        if (existing.avatarUrl === undefined) existing.avatarUrl = null;
      }
      await save(db);
    },
    publicUser,
  };
}

// ===== Supabase-backed store (remote)
function createSupabaseStore({ uid, sha256 }) {
  const baseUrl = String(process.env.SUPABASE_URL || '').replace(/\/$/, '');
  const serviceKey =
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_SERVICE_KEY ||
    process.env.SUPABASE_SERVICE_KEY_B64 || '';

  if (!baseUrl || !serviceKey) {
    throw new Error(
      'Supabase 모드를 사용하려면 SUPABASE_URL 과 SUPABASE_SERVICE_ROLE_KEY 환경 변수가 필요합니다.',
    );
  }

  const restUrl = `${baseUrl}/rest/v1`;
  const defaultHeaders = {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
  };

  function messageError(code, message) {
    const err = new Error(message || code);
    err.code = code;
    return err;
  }

  function messagesSchemaError() {
    return messageError(
      'messages-disabled',
      'Supabase 메시지 테이블이 아직 구성되지 않았습니다. Supabase SQL 콘솔에서 supabase/messages.sql 스키마를 적용해 주세요.',
    );
  }

  function profileSchemaError() {
    return messageError(
      'profile-disabled',
      'Supabase 프로필 테이블(user_follows)이 아직 구성되지 않았습니다. Supabase SQL 콘솔에서 supabase/profile.sql 스키마를 적용해 주세요.',
    );
  }

  function accountSchemaError() {
    return messageError(
      'account-disabled',
      'Supabase 계정 상태 테이블(user_actions) 또는 users.status/suspended_until 열이 아직 구성되지 않았습니다. Supabase SQL 콘솔에서 supabase/account.sql 스키마를 적용해 주세요.',
    );
  }

  function notificationsSchemaError() {
    return messageError(
      'notifications-disabled',
      'Supabase 알림 테이블(notifications)이 아직 구성되지 않았습니다. Supabase SQL 콘솔에서 supabase/notifications.sql 스키마를 적용해 주세요.',
    );
  }

  function systemSchemaError() {
    return messageError(
      'system-disabled',
      'Supabase 시스템 테이블(announcements, referral_codes)이 아직 구성되지 않았습니다. Supabase SQL 콘솔에서 supabase/system.sql 스키마를 적용해 주세요.',
    );
  }

  function isMessageTableMissingError(err) {
    if (!err || typeof err.message !== 'string') return false;
    return (
      /message_(channels|members|messages)/i.test(err.message) &&
      (/could not find the table/i.test(err.message) || /does not exist/i.test(err.message))
    );
  }

  function isProfileTableMissingError(err) {
    if (!err || typeof err.message !== 'string') return false;
    return /user_follows/i.test(err.message) &&
      (/could not find the table/i.test(err.message) || /does not exist/i.test(err.message));
  }

  function isAccountTableMissingError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (/user_actions/i.test(err.message) && (/could not find the table/i.test(err.message) || /does not exist/i.test(err.message))) {
      return true;
    }
    if (/column/i.test(err.message) && /status/i.test(err.message) && /users/i.test(err.message) && /does not exist/i.test(err.message)) {
      return true;
    }
    if (/column/i.test(err.message) && /suspended_/i.test(err.message) && /users/i.test(err.message) && /does not exist/i.test(err.message)) {
      return true;
    }
    return false;
  }

  function isNotificationsTableMissingError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (/notifications/i.test(err.message) && (/could not find the table/i.test(err.message) || /does not exist/i.test(err.message))) {
      return true;
    }
    if (/column/i.test(err.message) && /seen_at/i.test(err.message) && /notifications/i.test(err.message) && /does not exist/i.test(err.message)) {
      return true;
    }
    return false;
  }

  function isAnnouncementsTableMissingError(err) {
    if (!err || typeof err.message !== 'string') return false;
    return /announcements/i.test(err.message) && (/could not find the table/i.test(err.message) || /does not exist/i.test(err.message));
  }

  function isReferralCodesTableMissingError(err) {
    if (!err || typeof err.message !== 'string') return false;
    return /referral_codes/i.test(err.message) && (/could not find the table/i.test(err.message) || /does not exist/i.test(err.message));
  }

  function isReportsTableMissingError(err) {
    if (!err || typeof err.message !== 'string') return false;
    return /reports/i.test(err.message) && (/could not find the table/i.test(err.message) || /does not exist/i.test(err.message));
  }

function isConfigColumnMissingError(err) {
  if (!err || typeof err.message !== 'string') return false;
  if (!/column/i.test(err.message) || !/does not exist/i.test(err.message)) return false;
  return (
    /registration_mode/i.test(err.message) ||
    /invite_code_required/i.test(err.message) ||
    /basic_posting_restricted/i.test(err.message)
  );
}

  function isUniqueConstraintError(err) {
    if (!err || typeof err.message !== 'string') return false;
    return /23505/.test(err.message) && /duplicate key/i.test(err.message);
  }

  function handleMessageStoreError(err) {
    if (isMessageTableMissingError(err)) {
      throw messagesSchemaError();
    }
    if (isProfileTableMissingError(err)) {
      throw profileSchemaError();
    }
    if (isAccountTableMissingError(err)) {
      throw accountSchemaError();
    }
    if (isNotificationsTableMissingError(err)) {
      throw notificationsSchemaError();
    }
    if (isAnnouncementsTableMissingError(err) || isReferralCodesTableMissingError(err) || isReportsTableMissingError(err)) {
      throw systemSchemaError();
    }
    throw err;
  }

  function parseTagList(raw) {
    if (!raw) return [];
    if (Array.isArray(raw)) {
      return raw
        .map((tag) => (typeof tag === 'string' ? tag.trim() : ''))
        .filter((tag) => tag.length > 0);
    }
    if (typeof raw === 'string') {
      const trimmed = raw.trim();
      if (!trimmed) return [];
      // Try JSON first
      if ((trimmed.startsWith('[') && trimmed.endsWith(']')) || (trimmed.startsWith('"') && trimmed.endsWith('"'))) {
        try {
          const parsed = JSON.parse(trimmed);
          if (Array.isArray(parsed)) {
            return parsed
              .map((tag) => (typeof tag === 'string' ? tag.trim() : ''))
              .filter((tag) => tag.length > 0);
          }
        } catch {
          /* ignore malformed JSON */
        }
      }
      // Fallback: Postgres array literal {tag1,tag2}
      if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
        const inner = trimmed.slice(1, -1);
        if (!inner.trim()) return [];
        return inner
          .split(',')
          .map((part) =>
            part
              .trim()
              .replace(/^"(.*)"$/, '$1')
              .replace(/""/g, '"')
              .trim(),
          )
          .filter((tag) => tag.length > 0);
      }
      return [trimmed];
    }
    return [];
  }

  function quoteForIn(values) {
    return Array.from(new Set(values.filter(Boolean))).map((value) =>
      `"${String(value).replace(/"/g, '""')}"`,
    );
  }

  async function assertGroupNameAvailable(name) {
    const lower = name.trim().toLowerCase();
    const params = new URLSearchParams();
    params.set('select', 'id,name');
    params.set('type', 'eq.group');
    let rows = [];
    try {
      rows = await sb(`message_channels?${params.toString()}`);
    } catch (err) {
      handleMessageStoreError(err);
    }
    if (
      Array.isArray(rows) &&
      rows.some((row) => String(row?.name || '').trim().toLowerCase() === lower)
    ) {
      throw messageError('duplicate-name', '이미 사용 중인 그룹 이름입니다.');
    }
  }

  async function loadUsersByIds(ids) {
    const unique = quoteForIn(ids);
    if (!unique.length) return new Map();
    const params = new URLSearchParams();
    params.set('select', 'id,handle,name,avatar_url,role,is_superadmin');
    params.set('id', `in.(${unique.join(',')})`);
    try {
      const rows = await sb(`users?${params.toString()}`);
      const map = new Map();
      rows.forEach((row) => {
        const user = publicUser(row);
        if (user) map.set(user.id, user);
      });
      return map;
    } catch (err) {
      handleMessageStoreError(err);
    }
    return new Map();
  }

  async function fetchUserRowById(userId) {
    if (!userId) return null;
    const params = new URLSearchParams();
    params.set('select', 'id,handle,name,email,phone,avatar_url,created_at,status,deactivated_at,deleted_at,suspended_until,role,is_superadmin');
    params.set('id', `eq.${String(userId)}`);
    params.set('limit', '1');
    try {
      const rows = await sb(`users?${params.toString()}`);
      return rows?.[0] || null;
    } catch (err) {
      handleMessageStoreError(err);
      return null;
    }
  }

  async function fetchUserRowByHandle(handle) {
    if (!handle) return null;
    let normalized = String(handle || '').trim();
    if (!normalized) return null;
    if (!normalized.startsWith('@')) normalized = '@' + normalized;
    normalized = '@' + normalized.slice(1).toLowerCase();
    const params = new URLSearchParams();
    params.set('select', 'id,handle,name,email,phone,avatar_url,created_at,status,deactivated_at,deleted_at,suspended_until,role,is_superadmin');
    params.set('handle', `eq.${normalized}`);
    params.set('limit', '1');
    try {
      let rows = await sb(`users?${params.toString()}`);
      if ((!rows || !rows.length) && normalized.startsWith('@')) {
        const fallback = new URLSearchParams(params);
        fallback.set('handle', `eq.${normalized.slice(1)}`);
        rows = await sb(`users?${fallback.toString()}`);
      }
      return rows?.[0] || null;
    } catch (err) {
      handleMessageStoreError(err);
      return null;
    }
  }

  async function fetchUserAuthById(userId) {
    if (!userId) return null;
    const params = new URLSearchParams();
    params.set('select', 'id,handle,password_hash,email,phone,status,deactivated_at,deleted_at,suspended_until');
    params.set('id', `eq.${String(userId)}`);
    params.set('limit', '1');
    try {
      const rows = await sb(`users?${params.toString()}`);
      if (!rows || !rows.length) return null;
      const row = rows[0];
      return {
        id: row.id,
        handle: row.handle,
        passwordHash: row.password_hash || null,
        email: row.email || null,
        phone: row.phone || null,
        status: row.status || 'active',
        deactivatedAt: row.deactivated_at || null,
        deletedAt: row.deleted_at || null,
        suspendedUntil: row.suspended_until || null,
      };
    } catch (err) {
      handleMessageStoreError(err);
      return null;
    }
  }

  async function updateUserPasswordRemote(userId, newPasswordHash) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    if (!newPasswordHash) throw messageError('invalid-input', '비밀번호가 필요합니다.');
    const rows = await sb(`users?id=eq.${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      headers: { Prefer: 'return=minimal' },
      body: { password_hash: newPasswordHash },
    });
    return rows;
  }

  async function invalidateUserSessionsRemote(userId) {
    if (!userId) return;
    try {
      await sb(`sessions?user_id=eq.${encodeURIComponent(userId)}`, {
        method: 'DELETE',
        headers: { Prefer: 'return=minimal' },
      });
    } catch (err) {
      handleMessageStoreError(err);
    }
  }

  async function recordUserActionRemote({ userId, action, reason, detail, actorId, actorType, metadata }) {
    if (!userId) return;
    const payload = {
      id: 'act_' + uid(8),
      user_id: userId,
      action,
      reason: reason || null,
      detail: detail || null,
      actor_id: actorId || null,
      actor_type: actorType || (actorId ? 'user' : 'system'),
      metadata: metadata || null,
      created_at: new Date().toISOString(),
    };
    try {
      await sb('user_actions', {
        method: 'POST',
        headers: { Prefer: 'return=minimal' },
        body: payload,
      });
    } catch (err) {
      if (isAccountTableMissingError(err)) throw accountSchemaError();
      handleMessageStoreError(err);
    }
    if (shouldNotifyAdminAction(action)) {
      await createNotificationRemote({
        userId,
        type: 'admin-action',
        actorId: actorId || null,
        postId: null,
        commentId: null,
        payload: buildAdminActionNotificationPayload(action, { reason, detail }),
      });
    }
  }

  async function createNotificationRemote({ userId, type, actorId, postId, commentId, payload }) {
    if (!userId || !type) return;
    const body = {
      id: 'noti_' + uid(8),
      user_id: userId,
      type,
      actor_id: actorId || null,
      post_id: postId || null,
      comment_id: commentId || null,
      payload: payload || null,
      created_at: new Date().toISOString(),
      seen_at: null,
    };
    try {
      await sb('notifications', {
        method: 'POST',
        headers: { Prefer: 'return=minimal' },
        body,
      });
    } catch (err) {
      if (isNotificationsTableMissingError(err)) return;
      handleMessageStoreError(err);
    }
  }

  async function purgeUserContentRemote(userId) {
    const result = { postsRemoved: 0, commentsRemoved: 0 };
    if (!userId) return result;
    try {
      const deletedPosts = await sb(`posts?author_id=eq.${encodeURIComponent(userId)}`, {
        method: 'DELETE',
        headers: { Prefer: 'return=representation' },
      });
      if (Array.isArray(deletedPosts)) result.postsRemoved = deletedPosts.length;
    } catch (err) {
      handleMessageStoreError(err);
    }
    try {
      const deletedComments = await sb(`comments?author_id=eq.${encodeURIComponent(userId)}`, {
        method: 'DELETE',
        headers: { Prefer: 'return=representation' },
      });
      if (Array.isArray(deletedComments)) result.commentsRemoved = deletedComments.length;
    } catch (err) {
      handleMessageStoreError(err);
    }
    try {
      await sb(`notifications?user_id=eq.${encodeURIComponent(userId)}`, {
        method: 'DELETE',
        headers: { Prefer: 'return=minimal' },
      });
      await sb(`notifications?actor_id=eq.${encodeURIComponent(userId)}`, {
        method: 'DELETE',
        headers: { Prefer: 'return=minimal' },
      });
    } catch (err) {
      if (!isNotificationsTableMissingError(err)) handleMessageStoreError(err);
    }
    return result;
  }

  async function listNotificationsRemote(userId, { type = 'all', limit = 20, markSeen = true } = {}) {
    if (!userId) return [];
    const params = new URLSearchParams();
    params.set('select', 'id,user_id,type,actor_id,post_id,comment_id,payload,created_at,seen_at');
    params.set('user_id', `eq.${encodeURIComponent(userId)}`);
    params.set('order', 'created_at.desc');
    const normalizedType = typeof type === 'string' ? type : 'all';
    if (normalizedType !== 'all') params.set('type', `eq.${normalizedType}`);
    const max = Math.min(Math.max(Number(limit) || 0, 1), 100);
    params.set('limit', String(max));
    let rows = [];
    try {
      rows = await sb(`notifications?${params.toString()}`);
    } catch (err) {
      if (isNotificationsTableMissingError(err)) return [];
      handleMessageStoreError(err);
      return [];
    }
    if (!Array.isArray(rows) || !rows.length) return [];
    const actorIds = Array.from(new Set(rows.map((row) => row.actor_id).filter(Boolean)));
    const actorMap = actorIds.length ? await loadUsersByIds(actorIds) : new Map();
    const notifications = rows.map((row) => ({
      id: row.id,
      type: row.type,
      createdAt: row.created_at,
      seenAt: row.seen_at || null,
      actor: row.actor_id ? actorMap.get(row.actor_id) || null : null,
      postId: row.post_id || null,
      commentId: row.comment_id || null,
      payload: row.payload || null,
    }));
    if (markSeen) {
      const unseenIds = rows.filter((row) => !row.seen_at).map((row) => row.id);
      if (unseenIds.length) {
        const quoted = quoteForIn(unseenIds);
        try {
          await sb(`notifications?id=in.(${quoted.join(',')})`, {
            method: 'PATCH',
            headers: { Prefer: 'return=minimal' },
            body: { seen_at: new Date().toISOString() },
          });
        } catch (err) {
          if (!isNotificationsTableMissingError(err)) handleMessageStoreError(err);
        }
      }
    }
    return notifications;
  }

  async function countUnreadNotificationsRemote(userId) {
    if (!userId) return 0;
    try {
      return await countRows(`notifications?user_id=eq.${encodeURIComponent(userId)}&seen_at=is.null`);
    } catch (err) {
      if (isNotificationsTableMissingError(err)) return 0;
      if (isAccountTableMissingError(err)) throw accountSchemaError();
      handleMessageStoreError(err);
      return 0;
    }
  }

  function presentAnnouncementRow(row) {
    if (!row) return null;
    return {
      id: row.id,
      title: row.title || '',
      body: row.body || '',
      pinned: !!row.pinned,
      createdAt: row.created_at || null,
      updatedAt: row.updated_at || row.created_at || null,
      createdBy: row.created_by || null,
      updatedBy: row.updated_by || null,
    };
  }

  async function listAnnouncementsRemote({ pinnedOnly = false, limit } = {}) {
    const params = new URLSearchParams();
    params.set('select', 'id,title,body,pinned,created_at,updated_at,created_by,updated_by');
    params.set('order', 'pinned.desc,created_at.desc');
    if (pinnedOnly) params.set('pinned', 'eq.true');
    if (Number.isFinite(limit) && limit > 0) params.set('limit', String(Math.floor(limit)));
    try {
      const rows = await sb(`announcements?${params.toString()}`);
      if (!Array.isArray(rows)) return [];
      return rows.map(presentAnnouncementRow);
    } catch (err) {
      if (isReportsTableMissingError(err)) return [];
      handleMessageStoreError(err);
      return [];
    }
  }

  async function getAnnouncementRemote(id) {
    if (!id) return null;
    const params = new URLSearchParams();
    params.set('select', 'id,title,body,pinned,created_at,updated_at,created_by,updated_by');
    params.set('id', `eq.${encodeURIComponent(id)}`);
    params.set('limit', '1');
    try {
      const rows = await sb(`announcements?${params.toString()}`);
      if (!Array.isArray(rows) || !rows.length) return null;
      return presentAnnouncementRow(rows[0]);
    } catch (err) {
      if (isAnnouncementsTableMissingError(err)) return null;
      handleMessageStoreError(err);
      return null;
    }
  }

  async function createAnnouncementRemote({ title, body, pinned = false, actorId = null } = {}) {
    const nowIso = new Date().toISOString();
    const payload = {
      id: `ann_${uid(8)}`,
      title: String(title || '').trim(),
      body: String(body || '').trim(),
      pinned: !!pinned,
      created_at: nowIso,
      updated_at: nowIso,
      created_by: actorId || null,
      updated_by: actorId || null,
    };
    try {
      const rows = await sb('announcements', {
        method: 'POST',
        headers: { Prefer: 'return=representation' },
        body: payload,
      });
      const row = Array.isArray(rows) && rows[0] ? rows[0] : payload;
      return presentAnnouncementRow(row);
    } catch (err) {
      if (isAnnouncementsTableMissingError(err)) throw systemSchemaError();
      handleMessageStoreError(err);
      throw err;
    }
  }

  async function updateAnnouncementRemote(
    id,
    { title, body, pinned, actorId = null } = {},
  ) {
    if (!id) return null;
    const patch = {};
    if (title !== undefined) patch.title = String(title || '').trim();
    if (body !== undefined) patch.body = String(body || '').trim();
    if (pinned !== undefined) patch.pinned = !!pinned;
    patch.updated_at = new Date().toISOString();
    if (actorId !== undefined) patch.updated_by = actorId || null;
    try {
      const rows = await sb(`announcements?id=eq.${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=representation' },
        body: patch,
      });
      const row = Array.isArray(rows) && rows[0] ? rows[0] : null;
      return presentAnnouncementRow(row);
    } catch (err) {
      if (isAnnouncementsTableMissingError(err)) throw systemSchemaError();
      handleMessageStoreError(err);
      throw err;
    }
  }

  async function deleteAnnouncementRemote(id) {
    if (!id) return false;
    try {
      await sb(`announcements?id=eq.${encodeURIComponent(id)}`, { method: 'DELETE' });
      return true;
    } catch (err) {
      if (isReportsTableMissingError(err)) return false;
      handleMessageStoreError(err);
      throw err;
    }
  }

  function presentReferralCodeRow(row) {
    if (!row) return null;
    const limit = Number.isFinite(row.uses_limit) && row.uses_limit > 0 ? row.uses_limit : null;
    return {
      code: row.code,
      createdAt: row.created_at || null,
      expiresAt: row.expires_at || null,
      limit: limit ?? 'unlimited',
      used: Number(row.uses_count || 0),
      revoked: !!row.revoked,
      createdBy: row.created_by || null,
      lastUsedAt: row.last_used_at || null,
      metadata: row.metadata || null,
      notes: row.notes || null,
      usedBy: Array.isArray(row.used_by) ? row.used_by : [],
    };
  }

  async function listReferralCodesRemote() {
    const params = new URLSearchParams();
    params.set(
      'select',
      'code,created_at,expires_at,uses_limit,uses_count,revoked,created_by,last_used_at,metadata,notes,used_by',
    );
    params.set('order', 'created_at.desc');
    try {
      const rows = await sb(`referral_codes?${params.toString()}`);
      if (!Array.isArray(rows)) return [];
      return rows.map(presentReferralCodeRow);
    } catch (err) {
      if (isReferralCodesTableMissingError(err)) return [];
      handleMessageStoreError(err);
      return [];
    }
  }

  async function fetchReferralCodeRow(code) {
    const params = new URLSearchParams();
    params.set(
      'select',
      'code,created_at,expires_at,uses_limit,uses_count,revoked,created_by,last_used_at,metadata,notes,used_by',
    );
    params.set('code', `eq.${encodeURIComponent(code)}`);
    params.set('limit', '1');
    try {
      const rows = await sb(`referral_codes?${params.toString()}`);
      if (!Array.isArray(rows) || !rows.length) return null;
      return rows[0];
    } catch (err) {
      if (isReferralCodesTableMissingError(err)) return null;
      handleMessageStoreError(err);
      return null;
    }
  }

  async function createReferralCodeRemote({
    prefix = '',
    expiresAt = null,
    limit = null,
    actorId = null,
    notes = null,
  } = {}) {
    const normalizedPrefix = String(prefix || '')
      .trim()
      .replace(/[^0-9A-Za-z]/g, '')
      .toUpperCase();
    const nowIso = new Date().toISOString();
    let expiresIso = null;
    if (expiresAt) {
      const parsed = new Date(expiresAt);
      if (Number.isFinite(parsed.getTime())) expiresIso = parsed.toISOString();
    }
    let limitNormalized = null;
    if (limit !== null && limit !== undefined && limit !== 'unlimited') {
      const numeric = Number(limit);
      if (Number.isFinite(numeric) && numeric > 0) limitNormalized = Math.floor(numeric);
    }
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const base = uid(4).toUpperCase();
      const code = normalizedPrefix ? `${normalizedPrefix}-${base}` : base;
      const payload = {
        code,
        created_at: nowIso,
        expires_at: expiresIso,
        uses_limit: limitNormalized,
        uses_count: 0,
        revoked: false,
        created_by: actorId || null,
        last_used_at: null,
        metadata: null,
        notes: notes || null,
        used_by: [],
      };
      try {
        const rows = await sb('referral_codes', {
          method: 'POST',
          headers: { Prefer: 'return=representation' },
          body: payload,
        });
        const row = Array.isArray(rows) && rows[0] ? rows[0] : payload;
        return presentReferralCodeRow(row);
      } catch (err) {
        if (isReferralCodesTableMissingError(err)) throw systemSchemaError();
        if (isUniqueConstraintError(err)) {
          continue;
        }
        handleMessageStoreError(err);
        throw err;
      }
    }
    throw new Error('referral-code-generate-failed');
  }

  async function revokeReferralCodeRemote(code) {
    if (!code) return false;
    const normalized = String(code || '').trim().toUpperCase();
    try {
      await sb(`referral_codes?code=eq.${encodeURIComponent(normalized)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        body: { revoked: true },
      });
      return true;
    } catch (err) {
      if (isReferralCodesTableMissingError(err)) return false;
      handleMessageStoreError(err);
      throw err;
    }
  }

  async function verifyReferralCodeRemote(code) {
    if (!code) return { valid: false, reason: 'required', code: null };
    const normalized = String(code || '').trim().toUpperCase();
    const row = await fetchReferralCodeRow(normalized);
    if (!row) return { valid: false, reason: 'not-found', code: null };
    const state = {
      limit: Number.isFinite(row.uses_limit) && row.uses_limit > 0 ? row.uses_limit : null,
      used: Number(row.uses_count || 0),
      revoked: !!row.revoked,
      expiresAt: row.expires_at || null,
    };
    const status = isReferralCodeUsable(state);
    return {
      valid: status.ok,
      reason: status.reason,
      code: presentReferralCodeRow(row),
    };
  }

  async function consumeReferralCodeRemote(code, { userId = null } = {}) {
    if (!code) return { ok: false, reason: 'required' };
    const normalized = String(code || '').trim().toUpperCase();
    const row = await fetchReferralCodeRow(normalized);
    if (!row) return { ok: false, reason: 'not-found' };
    const state = {
      limit: Number.isFinite(row.uses_limit) && row.uses_limit > 0 ? row.uses_limit : null,
      used: Number(row.uses_count || 0),
      revoked: !!row.revoked,
      expiresAt: row.expires_at || null,
    };
    const status = isReferralCodeUsable(state);
    if (!status.ok) return { ok: false, reason: status.reason };
    const nowIso = new Date().toISOString();
    const usedBy = Array.isArray(row.used_by) ? row.used_by.slice() : [];
    if (userId) usedBy.push({ userId, usedAt: nowIso });
    try {
      const rows = await sb(`referral_codes?code=eq.${encodeURIComponent(normalized)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=representation' },
        body: {
          uses_count: Number(row.uses_count || 0) + 1,
          last_used_at: nowIso,
          used_by: usedBy,
        },
      });
      const nextCount = Number(row.uses_count || 0) + 1;
      const updated = Array.isArray(rows) && rows[0]
        ? rows[0]
        : { ...row, uses_count: nextCount, last_used_at: nowIso, used_by: usedBy };
      return { ok: true, code: presentReferralCodeRow(updated) };
    } catch (err) {
      if (isReferralCodesTableMissingError(err)) throw systemSchemaError();
      handleMessageStoreError(err);
      throw err;
    }
  }

  function parseSuspendUntil(until) {
    if (!until) return null;
    const date = new Date(until);
    const time = date.getTime();
    if (!Number.isFinite(time)) return null;
    return date.toISOString();
  }

  async function listAccountActionsRemote(userId) {
    if (!userId) return [];
    const params = new URLSearchParams();
    params.set('select', 'id,user_id,action,reason,detail,actor_id,actor_type,metadata,created_at');
    params.set('user_id', `eq.${encodeURIComponent(userId)}`);
    params.set('order', 'created_at.desc');
    try {
      const rows = await sb(`user_actions?${params.toString()}`);
      if (!Array.isArray(rows) || !rows.length) return [];
      const actorIds = Array.from(new Set(rows.map((row) => row.actor_id).filter(Boolean)));
      const actorMap = actorIds.length ? await loadUsersByIds(actorIds) : new Map();
      return rows.map((row) => {
        const actor = row.actor_id ? actorMap.get(row.actor_id) : null;
        return {
          id: row.id,
          action: row.action,
          reason: row.reason || null,
          detail: row.detail || null,
          actor: actor
            ? {
                id: actor.id,
                handle: actor.handle || null,
                name: actor.name || null,
              }
            : null,
          actorType: row.actor_type || (row.actor_id ? 'user' : 'system'),
          createdAt: row.created_at || null,
          metadata: row.metadata || null,
        };
      });
    } catch (err) {
      if (isAccountTableMissingError(err)) throw accountSchemaError();
      handleMessageStoreError(err);
      return [];
    }
  }

  async function getLatestAccountActionRemote(userId) {
    if (!userId) return null;
    const params = new URLSearchParams();
    params.set('select', 'id,user_id,action,reason,detail,actor_id,actor_type,metadata,created_at');
    params.set('user_id', `eq.${encodeURIComponent(userId)}`);
    params.set('order', 'created_at.desc');
    params.set('limit', '1');
    try {
      const rows = await sb(`user_actions?${params.toString()}`);
      if (!Array.isArray(rows) || !rows.length) return null;
      const row = rows[0];
      let actor = null;
      if (row.actor_id) {
        const actorMap = await loadUsersByIds([row.actor_id]);
        actor = actorMap.get(row.actor_id) || null;
      }
      return {
        id: row.id,
        action: row.action,
        reason: row.reason || null,
        detail: row.detail || null,
        actor: actor
          ? { id: actor.id, handle: actor.handle || null, name: actor.name || null }
          : null,
        actorType: row.actor_type || (row.actor_id ? 'user' : 'system'),
        createdAt: row.created_at || null,
        metadata: row.metadata || null,
      };
    } catch (err) {
      if (isAccountTableMissingError(err)) throw accountSchemaError();
      handleMessageStoreError(err);
      return null;
    }
  }

  async function deactivateAccountRemote(userId, { reason, actorId, actorType } = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const existing = await fetchUserAuthById(userId);
    if (!existing) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    if (existing.status === 'deleted') throw messageError('account-deleted', '이미 삭제된 계정입니다.');
    if (existing.status === 'deactivated') throw messageError('account-already-deactivated', '이미 비활성화된 계정입니다.');
    if (existing.status === 'suspended') throw messageError('account-suspended', '정지된 계정입니다.');
    const nowIso = new Date().toISOString();
    try {
      await sb(`users?id=eq.${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        body: { status: 'deactivated', deactivated_at: nowIso, suspended_until: null },
      });
      await recordUserActionRemote({
        userId,
        action: 'deactivated',
        reason: reason || null,
        actorId: actorId || userId,
        actorType: actorType || 'self',
      });
      await invalidateUserSessionsRemote(userId);
      const updated = await fetchUserRowById(userId);
      return publicUser(updated);
    } catch (err) {
      if (isAccountTableMissingError(err)) throw accountSchemaError();
      handleMessageStoreError(err);
      throw err;
    }
  }

  async function deleteAccountRemote(userId, { reason, detail, actorId, actorType } = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const existing = await fetchUserAuthById(userId);
    if (!existing) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    if (existing.status === 'deleted') throw messageError('account-deleted', '이미 삭제된 계정입니다.');
    const nowIso = new Date().toISOString();
    try {
      await sb(`users?id=eq.${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        body: {
          status: 'deleted',
          deleted_at: nowIso,
          deactivated_at: existing.deactivatedAt || nowIso,
          email: null,
          phone: null,
          avatar_url: null,
          suspended_until: null,
        },
      });
      const contentStats = await purgeUserContentRemote(userId);
      await recordUserActionRemote({
        userId,
        action: 'deleted',
        reason: reason || null,
        detail: detail || null,
        actorId: actorId || userId,
        actorType: actorType || 'self',
        metadata: {
          postsRemoved: contentStats.postsRemoved,
          commentsRemoved: contentStats.commentsRemoved,
        },
      });
      await invalidateUserSessionsRemote(userId);
      const updated = await fetchUserRowById(userId);
      return publicUser(updated);
    } catch (err) {
      if (isAccountTableMissingError(err)) throw accountSchemaError();
      handleMessageStoreError(err);
      throw err;
    }
  }

  async function suspendAccountRemote(userId, { reason, detail, until, actorId, actorType } = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const existing = await fetchUserAuthById(userId);
    if (!existing) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    if (existing.status === 'deleted') throw messageError('account-deleted', '이미 삭제된 계정입니다.');
    if (existing.status === 'suspended') throw messageError('account-already-suspended', '이미 정지된 계정입니다.');
    if (existing.status === 'banned') throw messageError('account-banned', '영구 정지된 계정입니다.');
    const nowIso = new Date().toISOString();
    const untilIso = parseSuspendUntil(until);
    try {
      await sb(`users?id=eq.${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        body: {
          status: 'suspended',
          suspended_until: untilIso,
          deactivated_at: existing.deactivatedAt || nowIso,
        },
      });
      await recordUserActionRemote({
        userId,
        action: 'suspension',
        reason: reason || null,
        detail: detail || null,
        actorId: actorId || null,
        actorType: actorType || (actorId ? 'user' : 'system'),
        metadata: untilIso ? { until: untilIso } : null,
      });
      await invalidateUserSessionsRemote(userId);
      const updated = await fetchUserRowById(userId);
      return publicUser(updated);
    } catch (err) {
      if (isAccountTableMissingError(err)) throw accountSchemaError();
      handleMessageStoreError(err);
      throw err;
    }
  }

  async function banAccountRemote(userId, { reason, detail, actorId, actorType } = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const existing = await fetchUserAuthById(userId);
    if (!existing) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    if (existing.status === 'deleted') throw messageError('account-deleted', '이미 삭제된 계정입니다.');
    if (existing.status === 'banned') throw messageError('account-banned', '이미 영구 정지된 계정입니다.');
    const nowIso = new Date().toISOString();
    try {
      await sb(`users?id=eq.${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        body: {
          status: 'banned',
          suspended_until: null,
          deactivated_at: existing.deactivatedAt || nowIso,
        },
      });
      await recordUserActionRemote({
        userId,
        action: 'banned',
        reason: reason || null,
        detail: detail || null,
        actorId: actorId || null,
        actorType: actorType || (actorId ? 'user' : 'system'),
      });
      await invalidateUserSessionsRemote(userId);
      const updated = await fetchUserRowById(userId);
      return publicUser(updated);
    } catch (err) {
      if (isAccountTableMissingError(err)) throw accountSchemaError();
      handleMessageStoreError(err);
      throw err;
    }
  }

  async function restoreAccountRemote(userId, { reason, detail, actorId, actorType } = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const existing = await fetchUserAuthById(userId);
    if (!existing) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
    if (existing.status === 'deleted') throw messageError('account-deleted', '이미 삭제된 계정입니다.');
    if (existing.status !== 'deactivated' && existing.status !== 'suspended' && existing.status !== 'banned') {
      throw messageError('account-active', '조치 상태의 계정이 아닙니다.');
    }
    try {
      await sb(`users?id=eq.${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        body: {
          status: 'active',
          deactivated_at: null,
          suspended_until: null,
        },
      });
      await recordUserActionRemote({
        userId,
        action: 'restored',
        reason: reason || null,
        detail: detail || null,
        actorId: actorId || null,
        actorType: actorType || (actorId ? 'user' : 'system'),
      });
      const updated = await fetchUserRowById(userId);
      return publicUser(updated);
    } catch (err) {
      if (isAccountTableMissingError(err)) throw accountSchemaError();
      handleMessageStoreError(err);
      throw err;
    }
  }

  function sanitizeFollowLimit(limit, fallback = 50) {
    if (!Number.isFinite(limit)) return Math.min(fallback, 200);
    if (limit <= 0) return null;
    return Math.min(Math.floor(limit), 200);
  }

  async function fetchViewerFollowingTargets(viewerId, targetIds) {
    if (!viewerId || !Array.isArray(targetIds) || !targetIds.length) return new Set();
    const quoted = quoteForIn(targetIds);
    if (!quoted.length) return new Set();
    const params = new URLSearchParams();
    params.set('select', 'target_id');
    params.set('follower_id', `eq.${encodeURIComponent(viewerId)}`);
    params.set('target_id', `in.(${quoted.join(',')})`);
    try {
      const rows = await sb(`user_follows?${params.toString()}`);
      return new Set((rows || []).map((row) => row?.target_id).filter(Boolean));
    } catch (err) {
      handleMessageStoreError(err);
    }
    return new Set();
  }

  async function fetchViewerFollowerIds(viewerId, followerIds) {
    if (!viewerId || !Array.isArray(followerIds) || !followerIds.length) return new Set();
    const quoted = quoteForIn(followerIds);
    if (!quoted.length) return new Set();
    const params = new URLSearchParams();
    params.set('select', 'follower_id');
    params.set('target_id', `eq.${encodeURIComponent(viewerId)}`);
    params.set('follower_id', `in.(${quoted.join(',')})`);
    try {
      const rows = await sb(`user_follows?${params.toString()}`);
      return new Set((rows || []).map((row) => row?.follower_id).filter(Boolean));
    } catch (err) {
      handleMessageStoreError(err);
    }
    return new Set();
  }

  async function listFollowersRemote(userId, { viewerId, limit = 50 } = {}) {
    if (!userId) return [];
    const params = new URLSearchParams();
    params.set(
      'select',
      'follower_id,target_id,created_at,follower:follower_id(id,handle,name,email,phone,avatar_url,created_at)',
    );
    params.set('target_id', `eq.${encodeURIComponent(userId)}`);
    params.set('order', 'created_at.desc');
    const safeLimit = sanitizeFollowLimit(limit);
    if (safeLimit) params.set('limit', String(safeLimit));
    let rows = [];
    try {
      rows = await sb(`user_follows?${params.toString()}`);
    } catch (err) {
      handleMessageStoreError(err);
    }
    const items = (rows || [])
      .map((row) => {
        const follower = row?.follower;
        if (!follower) return null;
        return {
          user: publicUser(follower),
          followedAt: row?.created_at || null,
        };
      })
      .filter(Boolean);
    if (!viewerId || !items.length) {
      return items.map((item) => ({
        ...item,
        isFollowing: false,
        isMutual: false,
      }));
    }
    const ids = items.map((item) => item.user?.id).filter(Boolean);
    const followingSet = await fetchViewerFollowingTargets(viewerId, ids);
    const followerSet = await fetchViewerFollowerIds(viewerId, ids);
    return items.map((item) => {
      const id = item.user?.id;
      const isFollowing = followingSet.has(id);
      const isMutual = isFollowing && followerSet.has(id);
      return {
        ...item,
        isFollowing,
        isMutual,
      };
    });
  }

  async function listFollowingRemote(userId, { viewerId, limit = 50 } = {}) {
    if (!userId) return [];
    const params = new URLSearchParams();
    params.set(
      'select',
      'follower_id,target_id,created_at,target:target_id(id,handle,name,email,phone,avatar_url,created_at)',
    );
    params.set('follower_id', `eq.${encodeURIComponent(userId)}`);
    params.set('order', 'created_at.desc');
    const safeLimit = sanitizeFollowLimit(limit);
    if (safeLimit) params.set('limit', String(safeLimit));
    let rows = [];
    try {
      rows = await sb(`user_follows?${params.toString()}`);
    } catch (err) {
      handleMessageStoreError(err);
    }
    const items = (rows || [])
      .map((row) => {
        const target = row?.target;
        if (!target) return null;
        return {
          user: publicUser(target),
          followedAt: row?.created_at || null,
        };
      })
      .filter(Boolean);
    if (!viewerId || !items.length) {
      return items.map((item) => ({
        ...item,
        isFollowing: false,
        isMutual: false,
      }));
    }
    const ids = items.map((item) => item.user?.id).filter(Boolean);
    const followingSet = await fetchViewerFollowingTargets(viewerId, ids);
    const followerSet = await fetchViewerFollowerIds(viewerId, ids);
    return items.map((item) => {
      const id = item.user?.id;
      const isFollowing = followingSet.has(id);
      const isMutual = followerSet.has(id);
      return {
        ...item,
        isFollowing,
        isMutual,
      };
    });
  }

  async function searchUsersRemote({ query, viewerId, excludeIds, limit = 10 } = {}) {
    const raw = String(query || '').trim();
    if (!raw) return [];
    const cleaned = raw.replace(/^@+/, '').trim();
    if (!cleaned) return [];
    const likeTerm = `*${cleaned}*`;
    const params = new URLSearchParams();
    params.set('select', 'id,handle,name,avatar_url,created_at,status,deactivated_at,deleted_at,suspended_until,role,is_superadmin');
    params.set('or', `(handle.ilike.${likeTerm},name.ilike.${likeTerm})`);
    params.set('limit', String(Math.min(Math.max(limit, 1) * 3, 50)));
    params.set('status', 'eq.active');
    let rows = [];
    try {
      rows = await sb(`users?${params.toString()}`);
    } catch (err) {
      handleMessageStoreError(err);
    }
    const excludeSet = new Set(Array.isArray(excludeIds) ? excludeIds.filter(Boolean) : []);
    if (viewerId) excludeSet.add(viewerId);
    const filtered = rows
      .filter((row) => row && (row.status || 'active') === 'active' && !excludeSet.has(row.id))
      .slice(0, Math.min(Math.max(limit, 1), 50));
    if (!filtered.length) return [];
    const presented = filtered.map((row) => presentUserForExplore(publicUser(row)));
    if (!viewerId) {
      return presented.map((user) => ({ ...user, isFollowing: false, isSelf: false }));
    }
    const followingSet = await fetchViewerFollowingTargets(
      viewerId,
      presented.map((user) => user.id),
    );
    return presented.map((user) => ({
      ...user,
      isFollowing: followingSet.has(user.id),
      isSelf: viewerId === user.id,
    }));
  }

  async function listRandomUsersRemote({ viewerId, excludeIds, limit = 6 } = {}) {
    const params = new URLSearchParams();
    params.set('select', 'id,handle,name,avatar_url,created_at,status,deactivated_at,deleted_at,suspended_until,role,is_superadmin');
    params.set('order', 'created_at.desc');
    params.set('limit', '200');
    params.set('status', 'eq.active');
    let rows = [];
    try {
      rows = await sb(`users?${params.toString()}`);
    } catch (err) {
      handleMessageStoreError(err);
    }
    const excludeSet = new Set(Array.isArray(excludeIds) ? excludeIds.filter(Boolean) : []);
    if (viewerId) excludeSet.add(viewerId);
    const filtered = rows.filter((row) => row && (row.status || 'active') === 'active' && !excludeSet.has(row.id));
    const sampled = sampleArray(filtered, Math.min(Math.max(limit || 0, 0), 20));
    if (!sampled.length) return [];
    const presented = sampled.map((row) => presentUserForExplore(publicUser(row)));
    if (!viewerId) {
      return presented.map((user) => ({ ...user, isFollowing: false, isSelf: false }));
    }
    const followingSet = await fetchViewerFollowingTargets(
      viewerId,
      presented.map((user) => user.id),
    );
    return presented.map((user) => ({
      ...user,
      isFollowing: followingSet.has(user.id),
      isSelf: viewerId === user.id,
    }));
  }

  async function fetchRecentPosts(limit = 200) {
    const params = new URLSearchParams();
    params.set('select', 'id,text,created_at,author_id,author_handle,author_name,author_avatar_url');
    params.set('order', 'created_at.desc');
    params.set('limit', String(Math.min(Math.max(limit, 1), 200)));
    let rows = [];
    try {
      rows = await sb(`posts?${params.toString()}`);
    } catch (err) {
      handleMessageStoreError(err);
    }
    if (!Array.isArray(rows)) return [];
    return rows.map((row) => ({
      id: row.id,
      text: row.text || '',
      createdAt: row.created_at || null,
      author: {
        id: row.author_id,
        handle: row.author_handle,
        name: row.author_name,
        avatarUrl: row.author_avatar_url || null,
      },
    }));
  }

  async function searchPostsRemote({ query, tag, limit = 10 } = {}) {
    const raw = String(query || '').trim();
    const tagRaw = tag ? String(tag).replace(/^#/, '').toLowerCase() : null;
    if (!raw && !tagRaw) return [];
    const posts = await fetchRecentPosts(Math.max(limit * 6, 60));
    if (!Array.isArray(posts) || !posts.length) return [];
    const normalized = raw.toLowerCase();
    const handleSearch = normalized.startsWith('@')
      ? normalized.replace(/^@+/, '')
      : null;
    const results = [];
    for (const post of posts) {
      if (results.length >= Math.min(Math.max(limit || 0, 1), 50)) break;
      const text = String(post?.text || '');
      const authorHandle = String(post?.author?.handle || '').toLowerCase();
      const tags = extractHashtags(text);
      const hasTag = tagRaw
        ? tags.some((t) => t.replace(/^#/, '') === tagRaw)
        : false;
      let matches = false;
      if (tagRaw) {
        matches = hasTag;
      }
      if (!matches && raw) {
        if (handleSearch) {
          matches = authorHandle.includes(handleSearch);
        } else {
          matches = text.toLowerCase().includes(normalized);
        }
      }
      if (!matches) continue;
      results.push({
        id: post.id,
        text,
        createdAt: post.createdAt || null,
        author: post.author || null,
        tags,
      });
    }
    return results;
  }

  async function searchTagsRemote({ query, limit = 10 } = {}) {
    const posts = await fetchRecentPosts(200);
    const counts = aggregateHashtagCounts(posts);
    if (!counts.size) return [];
    const entries = Array.from(counts.entries()).map(([tagValue, count]) => ({
      tag: tagValue,
      count,
    }));
    const normalized = String(query || '').trim().toLowerCase();
    const filtered = normalized
      ? entries.filter((entry) =>
          entry.tag.includes(normalized.startsWith('#') ? normalized : `#${normalized}`),
        )
      : entries;
    return filtered
      .sort((a, b) => b.count - a.count)
      .slice(0, Math.min(Math.max(limit || 0, 1), 50));
  }

  async function getTrendingTagsRemote({ limit = 10 } = {}) {
    return searchTagsRemote({ query: '', limit });
  }

  async function countFollowersRemote(userId) {
    try {
      return await countRows(`user_follows?target_id=eq.${encodeURIComponent(userId)}`);
    } catch (err) {
      if (isProfileTableMissingError(err)) return 0;
      handleMessageStoreError(err);
      return 0;
    }
  }

  async function countFollowingRemote(userId) {
    try {
      return await countRows(`user_follows?follower_id=eq.${encodeURIComponent(userId)}`);
    } catch (err) {
      if (isProfileTableMissingError(err)) return 0;
      handleMessageStoreError(err);
      return 0;
    }
  }

  async function isFollowingRemote(followerId, targetId) {
    if (!followerId || !targetId) return false;
    try {
      const rows = await sb(
        `user_follows?select=target_id&follower_id=eq.${encodeURIComponent(followerId)}&target_id=eq.${encodeURIComponent(targetId)}&limit=1`,
      );
      return Array.isArray(rows) && rows.length > 0;
    } catch (err) {
      if (isProfileTableMissingError(err)) return false;
      handleMessageStoreError(err);
      return false;
    }
  }

  async function listPostsByAuthorRemote(userId, { limit = 20 } = {}) {
    if (!userId) return [];
    if (limit === 0) return [];
    const params = new URLSearchParams();
    params.set(
      'select',
      'id,text,attachments,created_at,author_id,author_handle,author_name,author_avatar_url,comments(id,post_id,author_type,author_id,author_handle,author_name,author_avatar_url,text,created_at,guest_pw_hash)',
    );
    params.set('author_id', `eq.${String(userId)}`);
    params.set('status', 'neq.removed');
    params.set('order', 'created_at.desc');
    if (typeof limit === 'number' && limit > 0) params.set('limit', String(Math.min(Math.max(limit, 1), 50)));
    try {
      const rows = await sb(`posts?${params.toString()}`);
      return Array.isArray(rows) ? rows.map(mapPost) : [];
    } catch (err) {
      handleMessageStoreError(err);
      return [];
    }
  }

  async function getUserProfileViewRemote({ handle, userId, viewerId, limit = 20 }) {
    let userRow = null;
    if (userId) {
      userRow = await fetchUserRowById(userId);
    }
    if (!userRow && handle) {
      userRow = await fetchUserRowByHandle(handle);
    }
    if (!userRow) return null;

    const targetId = userRow.id;
    const followerCount = await countFollowersRemote(targetId);
    const followingCount = await countFollowingRemote(targetId);
    let postsCount = 0;
    try {
      postsCount = await countRows(`posts?author_id=eq.${encodeURIComponent(targetId)}&status=neq.removed`);
    } catch (err) {
      handleMessageStoreError(err);
    }
    const posts = await listPostsByAuthorRemote(targetId, { limit }).then((list) =>
      list.map((post) => ({
        ...post,
        author: {
          id: targetId,
          handle: userRow.handle,
          name: userRow.name,
          avatarUrl: userRow.avatar_url || null,
        },
      })),
    );
    const viewerRow = viewerId ? await fetchUserRowById(viewerId) : null;
    const isFollowing = viewerId ? await isFollowingRemote(viewerId, targetId) : false;
    return {
      user: publicUser(userRow),
      stats: {
        followers: followerCount,
        following: followingCount,
        posts: Number.isFinite(postsCount) ? postsCount : posts.length,
      },
      isFollowing,
      posts,
      viewer: viewerRow ? publicUser(viewerRow) : null,
    };
  }

  async function followUserRemote(followerId, targetId) {
    if (!followerId || !targetId) throw messageError('invalid-input', '대상 정보가 부족합니다.');
    if (followerId === targetId) throw messageError('invalid-target', '자기 자신을 팔로우할 수 없습니다.');
    const alreadyFollowing = await isFollowingRemote(followerId, targetId);
    if (!alreadyFollowing) {
      let inserted = false;
      try {
        await sb('user_follows', {
          method: 'POST',
          headers: { Prefer: 'return=minimal' },
          body: { follower_id: followerId, target_id: targetId, created_at: new Date().toISOString() },
        });
        inserted = true;
      } catch (err) {
        if (!isUniqueConstraintError(err)) handleMessageStoreError(err);
      }
      if (inserted && followerId !== targetId) {
        await createNotificationRemote({
          userId: targetId,
          type: 'follow',
          actorId: followerId,
          payload: null,
        });
      }
    }
    return getUserProfileViewRemote({ userId: targetId, viewerId: followerId, limit: 0 });
  }

  async function unfollowUserRemote(followerId, targetId) {
    if (!followerId || !targetId) throw messageError('invalid-input', '대상 정보가 부족합니다.');
    if (followerId === targetId) throw messageError('invalid-target', '자기 자신을 팔로우할 수 없습니다.');
    try {
      await sb(
        `user_follows?follower_id=eq.${encodeURIComponent(followerId)}&target_id=eq.${encodeURIComponent(targetId)}`,
        { method: 'DELETE', headers: { Prefer: 'return=minimal' } },
      );
    } catch (err) {
      handleMessageStoreError(err);
    }
    return getUserProfileViewRemote({ userId: targetId, viewerId: followerId, limit: 0 });
  }

  async function updateUserRow(userId, updates = {}) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const body = {};
    if (updates.name !== undefined) body.name = updates.name;
    if (updates.handle !== undefined) body.handle = updates.handle;
    if (updates.email !== undefined) body.email = updates.email;
    if (updates.phone !== undefined) body.phone = updates.phone;
    if (updates.avatarUrl !== undefined) body.avatar_url = updates.avatarUrl;
    if (Object.keys(body).length === 0) {
      const existing = await fetchUserRowById(userId);
      return existing ? publicUser(existing) : null;
    }
    const rows = await sb(`users?id=eq.${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      headers: { Prefer: 'return=representation' },
      body,
    });
    if (!rows || !rows.length) return null;
    return publicUser(rows[0]);
  }

  async function loadChannelRow(channelId) {
    const params = new URLSearchParams();
    params.set('select', 'id,type,name,desc,tags,avatar,locked,created_at,created_by');
    params.set('id', `eq.${channelId}`);
    params.set('limit', '1');
    try {
      const rows = await sb(`message_channels?${params.toString()}`);
      return rows[0] || null;
    } catch (err) {
      handleMessageStoreError(err);
    }
    return null;
  }

  async function ensureMembership(channelId, userId) {
    if (!channelId || !userId) return;
    const params = new URLSearchParams();
    params.set('select', 'channel_id,user_id');
    params.set('channel_id', `eq.${channelId}`);
    params.set('user_id', `eq.${userId}`);
    try {
      const existing = await sb(`message_members?${params.toString()}`);
      if (existing.length) return;
      try {
        await sb('message_members', {
          method: 'POST',
          headers: { Prefer: 'return=minimal' },
          body: {
            channel_id: channelId,
            user_id: userId,
            joined_at: new Date().toISOString(),
          },
        });
      } catch (err) {
        if (isUniqueConstraintError(err)) return;
        handleMessageStoreError(err);
      }
    } catch (err) {
      handleMessageStoreError(err);
    }
  }

  async function fetchMembersForChannels(channelIds) {
    const map = new Map();
    const quoted = quoteForIn(channelIds);
    if (!quoted.length) return map;
    const params = new URLSearchParams();
    params.set('select', 'channel_id,user_id');
    params.set('channel_id', `in.(${quoted.join(',')})`);
    try {
      const rows = await sb(`message_members?${params.toString()}`);
      rows.forEach((row) => {
        const list = map.get(row.channel_id) || [];
        list.push(row.user_id);
        map.set(row.channel_id, list);
      });
    } catch (err) {
      handleMessageStoreError(err);
    }
    channelIds.forEach((id) => {
      if (!map.has(id)) map.set(id, []);
    });
    return map;
  }

  async function fetchMembersForChannel(channelId) {
    const params = new URLSearchParams();
    params.set('select', 'channel_id,user_id');
    params.set('channel_id', `eq.${channelId}`);
    try {
      const rows = await sb(`message_members?${params.toString()}`);
      return rows.map((row) => row.user_id);
    } catch (err) {
      handleMessageStoreError(err);
    }
    return [];
  }

  async function fetchLastMessages(channelIds) {
    const map = new Map();
    const quoted = quoteForIn(channelIds);
    if (!quoted.length) return map;
    const params = new URLSearchParams();
    params.set('select', 'id,channel_id,text,created_at');
    params.set('channel_id', `in.(${quoted.join(',')})`);
    params.set('order', 'created_at.desc');
    params.set('limit', String(Math.max(200, channelIds.length * 4)));
    try {
      const rows = await sb(`message_messages?${params.toString()}`);
      for (const row of rows) {
        if (!map.has(row.channel_id)) {
          map.set(row.channel_id, {
            id: row.id,
            text: row.text,
            createdAt: row.created_at,
          });
        }
      }
    } catch (err) {
      handleMessageStoreError(err);
    }
    return map;
  }

  async function createGroupChannel({ userId, name, desc, tags }) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    let normalizedName;
    try {
      normalizedName = normalizeGroupName(name);
    } catch (err) {
      throw messageError(err.code || 'invalid-name', err.message || '그룹 이름을 확인해 주세요.');
    }
    const normalizedDesc = normalizeGroupDesc(desc);
    const normalizedTags = normalizeGroupTags(tags);
    await assertGroupNameAvailable(normalizedName);
    const channelId = 'grp_' + uid(6);
    const payload = {
      id: channelId,
      type: 'group',
      name: normalizedName,
      desc: normalizedDesc,
      tags: normalizedTags,
      avatar: null,
      locked: false,
      created_at: new Date().toISOString(),
      created_by: userId,
    };
    try {
      await sb('message_channels', {
        method: 'POST',
        headers: { Prefer: 'return=minimal' },
        body: payload,
      });
    } catch (err) {
      handleMessageStoreError(err);
    }
    await ensureMembership(channelId, userId);
    const row = await loadChannelRow(channelId);
    const memberIds = await fetchMembersForChannel(channelId);
    const memberMap = new Map([[channelId, memberIds]]);
    const userMap = await loadUsersByIds(memberIds.filter((id) => id && id !== userId));
    const lastMap = new Map();
    const meta = buildChannelMeta(row, {
      viewerId: userId,
      memberMap,
      userMap,
      lastMap,
      includeWhenNotJoined: true,
    });
    return meta;
  }

  async function leaveGroupChannel(channelId, userId) {
    if (!channelId) throw messageError('channel-required', '채널 ID가 필요합니다.');
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const row = await loadChannelRow(channelId);
    if (!row) throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
    if (row.type !== 'group') {
      throw messageError('invalid-channel', '그룹 채널만 나갈 수 있습니다.');
    }
    const params = new URLSearchParams();
    params.set('select', 'channel_id,user_id');
    params.set('channel_id', `eq.${channelId}`);
    params.set('user_id', `eq.${userId}`);
    let existing = [];
    try {
      existing = await sb(`message_members?${params.toString()}`);
    } catch (err) {
      handleMessageStoreError(err);
    }
    if (!existing.length) {
      throw messageError('not-member', '참여 중인 그룹이 아닙니다.');
    }
    try {
      await sb(`message_members?${params.toString()}`, {
        method: 'DELETE',
        headers: { Prefer: 'return=minimal' },
      });
    } catch (err) {
      handleMessageStoreError(err);
    }
    return true;
  }

  function buildChannelMeta(row, { viewerId, memberMap, userMap, lastMap, includeWhenNotJoined = false }) {
    if (!row) return null;
    const members = memberMap.get(row.id) || [];
    const joined =
      row.type === 'square'
        ? true
        : row.type === 'dm'
        ? members.includes(viewerId)
        : members.includes(viewerId);
    if (!joined && !includeWhenNotJoined) return null;

    const tags = parseTagList(row.tags);
    const last = lastMap.get(row.id) || null;
    const counterpartId =
      row.type === 'dm' ? members.find((memberId) => memberId && memberId !== viewerId) : null;
    const counterpart = counterpartId ? userMap.get(counterpartId) : null;
    const fallbackName = row.type === 'dm' ? '다이렉트 메시지' : '채널';

    let displayName = row.name || (counterpart ? counterpart.name || counterpart.handle : fallbackName);
    let displayDesc = row.desc || (counterpart ? counterpart.handle || '다이렉트 메시지' : row.desc || '');
    if (row.type === 'dm' && !displayDesc) displayDesc = '다이렉트 메시지';

    return {
      id: row.id,
      type: row.type,
      name: displayName,
      desc: displayDesc,
      avatar: row.avatar || null,
      tags,
      memberCount: members.length,
      joined,
      locked: !!row.locked,
      lastMessageAt: last ? last.createdAt : row.created_at || null,
      lastMessagePreview: last ? String(last.text || '').slice(0, 120) : null,
      counterpart: counterpart
        ? {
            id: counterpart.id,
            handle: counterpart.handle,
            name: counterpart.name,
            avatarUrl: counterpart.avatarUrl || null,
          }
        : null,
      createdAt: row.created_at || null,
    };
  }

  function mapMessageRow(row, authorMap) {
    if (!row) return null;
    const author = row.author_id ? authorMap.get(row.author_id) : null;
    return {
      id: row.id,
      channelId: row.channel_id,
      text: row.text,
      createdAt: row.created_at,
      author: author
        ? {
            id: author.id,
            handle: author.handle,
            name: author.name,
            avatarUrl: author.avatarUrl || null,
          }
        : null,
    };
  }

  function buildAdminChannelEntryRemote(row, memberIds, userMap, lastMessage) {
    if (!row || row.id === 'square') return null;
    const parsedTags = parseTagList(row.tags);
    const members = (memberIds || []).map((memberId) => {
      const info = userMap.get(memberId);
      if (info) return info;
      return {
        id: memberId,
        handle: null,
        name: null,
        role: null,
        status: null,
        createdAt: null,
        suspendedUntil: null,
        isSuperAdmin: false,
      };
    });
    const memberLabels = members.map((m) => m?.handle || m?.name || m?.id).filter(Boolean);
    const fallbackName =
      row.type === 'dm'
        ? memberLabels.join(', ') || '다이렉트 메시지'
        : row.name || '채널';
    const name = row.name && row.name.trim().length ? row.name : fallbackName;
    const desc =
      row.desc ||
      (row.type === 'dm' ? '다이렉트 메시지' : (row.desc || ''));
    const preview = lastMessage ? String(lastMessage.text || '').slice(0, 160) : null;
    const lastAt = lastMessage?.createdAt || row.created_at || null;
    return {
      id: row.id,
      type: row.type,
      name,
      desc,
      tags: parsedTags,
      locked: !!row.locked,
      memberCount: members.length,
      members,
      lastMessageAt: lastAt,
      lastMessagePreview: preview,
      createdAt: row.created_at || null,
    };
  }

  async function adminListMessageChannelsRemote() {
    const params = new URLSearchParams();
    params.set('select', 'id,type,name,desc,tags,avatar,locked,created_at,created_by');
    params.set('order', 'created_at.desc');
    params.set('id', 'neq.square');
    let rows = [];
    try {
      rows = await sb(`message_channels?${params.toString()}`);
    } catch (err) {
      handleMessageStoreError(err);
    }
    if (!Array.isArray(rows) || !rows.length) return [];
    const channelIds = rows.map((row) => row.id);
    const memberMap = await fetchMembersForChannels(channelIds);
    const memberIdSet = new Set();
    memberMap.forEach((list) => (list || []).forEach((id) => id && memberIdSet.add(id)));
    const userMap = await loadUsersByIds(Array.from(memberIdSet));
    const lastMap = await fetchLastMessages(channelIds);
    const items = rows
      .map((row) => {
        const members = memberMap.get(row.id) || [];
        const last = lastMap.get(row.id) || null;
        return buildAdminChannelEntryRemote(row, members, userMap, last);
      })
      .filter(Boolean)
      .sort((a, b) => {
        const at = new Date(a.lastMessageAt || a.createdAt || 0).getTime();
        const bt = new Date(b.lastMessageAt || b.createdAt || 0).getTime();
        return bt - at;
      });
    return items;
  }

  async function adminListChannelMessagesRemote(channelId, { limit = 200 } = {}) {
    if (!channelId) throw messageError('channel-required', '채널 ID가 필요합니다.');
    const row = await loadChannelRow(channelId);
    if (!row || row.id === 'square') {
      throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
    }
    const memberIds =
      row.type === 'square'
        ? []
        : await fetchMembersForChannel(channelId);
    const params = new URLSearchParams();
    params.set('select', 'id,channel_id,author_id,text,created_at');
    params.set('channel_id', `eq.${channelId}`);
    params.set('order', 'created_at.desc');
    const capped =
      Number.isFinite(limit) && Number(limit) > 0
        ? Math.max(1, Math.min(500, Math.floor(Number(limit))))
        : 200;
    params.set('limit', String(capped));
    let messageRows = [];
    try {
      messageRows = await sb(`message_messages?${params.toString()}`);
    } catch (err) {
      handleMessageStoreError(err);
    }
    const authorIds = new Set(memberIds);
    messageRows.forEach((entry) => {
      if (entry?.author_id) authorIds.add(entry.author_id);
    });
    const userMap = await loadUsersByIds(Array.from(authorIds));
    const mapped = messageRows.map((rowData) => mapMessageRow(rowData, userMap)).filter(Boolean);
    const messages = mapped.reverse();
    const lastForMeta = messages.length
      ? { text: messages[messages.length - 1].text, createdAt: messages[messages.length - 1].createdAt }
      : null;
    const channel = buildAdminChannelEntryRemote(row, memberIds, userMap, lastForMeta);
    return { channel, messages };
  }

  async function seedMessageChannels() {
    const nowIso = new Date().toISOString();
    try {
      const squareRows = await sb(
        `message_channels?select=id&limit=1&id=eq.${encodeURIComponent('square')}`,
      );
      if (!squareRows.length) {
        await sb('message_channels', {
          method: 'POST',
          headers: { Prefer: 'return=minimal' },
          body: {
            id: 'square',
            type: 'square',
            name: '모두의 광장',
            desc: 'Looma 전체 공개 채널',
            tags: ['광장', '공지'],
            avatar: '🌐',
            locked: true,
            created_at: nowIso,
            created_by: null,
          },
        });
      }
      for (const seed of DEFAULT_MESSAGE_GROUP_SEEDS) {
        const existing = await sb(
          `message_channels?select=id&limit=1&id=eq.${encodeURIComponent(seed.id)}`,
        );
        if (!existing.length) {
          await sb('message_channels', {
            method: 'POST',
            headers: { Prefer: 'return=minimal' },
            body: {
              id: seed.id,
              type: seed.type,
              name: seed.name,
              desc: seed.desc,
              tags: Array.isArray(seed.tags) ? seed.tags : [],
              avatar: seed.avatar || null,
              locked: !!seed.locked,
              created_at: nowIso,
              created_by: 'u1',
            },
          });
        }
      }
    } catch (err) {
      if (isMessageTableMissingError(err)) return;
      throw err;
    }
  }

  const normalizePollForStore = (raw) => normalizePollAttachment(raw);
  const normalizeAttachmentForStore = (att) => {
    if (!att || typeof att !== 'object') return null;
    if (att.type === 'poll') return normalizePollForStore(att);
    return normalizeFileAttachment(att);
  };
  const normalizeAttachmentsFromRow = (list) =>
    Array.isArray(list)
      ? list.map((att) => normalizeAttachmentForStore(att)).filter(Boolean)
      : [];

  async function sb(path, { method = 'GET', headers = {}, body } = {}) {
    const res = await fetch(`${restUrl}/${path}`, {
      method,
      headers: {
        ...defaultHeaders,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...headers,
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      const err = new Error(`Supabase ${method} ${path} 실패 (${res.status}): ${text}`);
      try {
        handleMessageStoreError(err);
      } catch (handled) {
        throw handled;
      }
      throw err;
    }
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      return res.json();
    }
    return null;
  }

  async function countRows(path) {
    const res = await fetch(`${restUrl}/${path}`, {
      method: 'HEAD',
      headers: {
        ...defaultHeaders,
        Prefer: 'count=exact',
      },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      const err = new Error(`Supabase HEAD ${path} 실패 (${res.status}): ${text}`);
      if (isProfileTableMissingError(err)) return 0;
      handleMessageStoreError(err);
      throw err;
    }
    const range = res.headers.get('content-range');
    if (range) {
      const totalPart = range.split('/').pop();
      const total = Number(totalPart);
      if (Number.isFinite(total)) return total;
    }
    const countHeader = res.headers.get('content-count');
    if (countHeader) {
      const total = Number(countHeader);
      if (Number.isFinite(total)) return total;
    }
    return 0;
  }

  function publicUser(row) {
    if (!row) return null;
    return {
      id: row.id,
      handle: row.handle,
      name: row.name,
      email: row.email || null,
      phone: row.phone || null,
      avatarUrl: row.avatar_url || null,
      createdAt: row.created_at || null,
      status: row.status || 'active',
      deactivatedAt: row.deactivated_at || null,
      deletedAt: row.deleted_at || null,
      suspendedUntil: row.suspended_until || row.suspendedUntil || null,
      role: row.role || null,
      isSuperAdmin: !!(row.is_superadmin || row.isSuperAdmin),
    };
  }

  function mapComment(row) {
    if (!row) return null;
    const out = {
      id: row.id,
      postId: row.post_id,
      authorType: row.author_type,
      text: row.text,
      createdAt: row.created_at,
    };
    if (row.author_type === 'user') {
      out.author = {
        id: row.author_id,
        handle: row.author_handle,
        name: row.author_name,
        avatarUrl: row.author_avatar_url || null,
      };
    } else if (row.author_type === 'guest') {
      out.guestPwHash = row.guest_pw_hash;
    }
    return out;
  }

  function mapPost(row) {
    if (!row) return null;
    return {
      id: row.id,
      author: {
        id: row.author_id,
        handle: row.author_handle,
        name: row.author_name,
        avatarUrl: row.author_avatar_url || null,
      },
      text: row.text,
      createdAt: row.created_at,
      attachments: normalizeAttachmentsFromRow(row.attachments),
      comments: Array.isArray(row.comments) ? row.comments.map(mapComment) : [],
      status: row.status || 'active',
    };
  }

  function presentUserForAdminRemote(row) {
    const user = publicUser(row);
    if (!user) return null;
    return {
      id: user.id,
      handle: user.handle || null,
      name: user.name || null,
      email: user.email || null,
      role: user.role || 'user',
      status: user.status || 'active',
      createdAt: user.createdAt || null,
      suspendedUntil: user.suspendedUntil || null,
      isSuperAdmin: !!user.isSuperAdmin,
    };
  }

  function mapReportRowToAdmin(row) {
    if (!row) return null;
    return {
      id: row.id,
      type: row.type || 'post',
      status: row.status || 'open',
      reason: row.reason || null,
      detail: row.detail || null,
      summary: row.summary || '',
      createdAt: row.created_at || null,
      updatedAt: row.updated_at || row.created_at || null,
      reporter: {
        name: row.reporter_name || row.reporter_handle || null,
        handle: row.reporter_handle || null,
        userId: row.reporter_user_id || null,
      },
      target: {
        type: row.target_type || (row.post_id ? 'post' : 'user'),
        id: row.target_id || row.post_id || null,
        userId: row.target_user_id || null,
        handle: row.target_handle || null,
        name: row.target_name || null,
      },
      postId: row.post_id || null,
    };
  }

  async function adminListReportsRemote({ query, type, status, limit = 100 } = {}) {
    const params = new URLSearchParams();
    params.set(
      'select',
      'id,type,status,summary,reason,detail,reporter_type,reporter_user_id,reporter_handle,reporter_name,target_type,target_id,target_user_id,target_handle,target_name,post_id,comment_id,created_at,updated_at',
    );
    params.set('order', 'created_at.desc');
    params.set('limit', String(Math.min(Math.max(limit || 0, 1) * 3, 500)));
    if (type) params.set('type', `eq.${encodeURIComponent(String(type))}`);
    if (status) params.set('status', `eq.${encodeURIComponent(String(status))}`);
    if (query) {
      const sanitized = String(query).trim().replace(/[()]/g, '');
      if (sanitized) {
        const like = `*${sanitized.replace(/\*/g, '')}*`;
        params.set(
          'or',
          `(summary.ilike.${like},reason.ilike.${like},reporter_handle.ilike.${like},reporter_name.ilike.${like},target_handle.ilike.${like},target_name.ilike.${like})`,
        );
      }
    }
    let rows = [];
    try {
      rows = await sb(`reports?${params.toString()}`);
    } catch (err) {
      if (isAnnouncementsTableMissingError(err)) return [];
      handleMessageStoreError(err);
      return [];
    }
    let items = Array.isArray(rows) ? rows.map(mapReportRowToAdmin).filter(Boolean) : [];
    if (query) {
      const lowerQuery = String(query).toLowerCase();
      items = items.filter((item) => {
        const haystack = [
          item.summary || '',
          item.reason || '',
          item.detail || '',
          item.reporter?.handle || '',
          item.reporter?.name || '',
          item.target?.handle || '',
          item.target?.name || '',
        ]
          .join(' ')
          .toLowerCase();
        return haystack.includes(lowerQuery);
      });
    }
    items.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    const max = Math.min(Math.max(limit || 0, 0), 500);
    return max ? items.slice(0, max) : items;
  }

  async function adminResolveReportRemote(reportId, status = 'closed') {
    if (!reportId) return false;
    try {
      await sb(`reports?id=eq.${encodeURIComponent(reportId)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        body: { status, updated_at: new Date().toISOString() },
      });
      return true;
    } catch (err) {
      if (isAnnouncementsTableMissingError(err)) return false;
      handleMessageStoreError(err);
      throw err;
    }
  }

  async function adminListUsersRemote({ query, role, status, limit = 100 } = {}) {
    const params = new URLSearchParams();
    params.set('select', 'id,handle,name,email,phone,avatar_url,created_at,status,deactivated_at,deleted_at,suspended_until,role,is_superadmin');
    params.set('order', 'created_at.desc');
    params.set('limit', String(Math.min(Math.max(limit || 0, 1) * 3, 500))); 
    if (status) params.set('status', `eq.${encodeURIComponent(String(status))}`);
    if (query) {
      const sanitized = String(query).trim().replace(/[()]/g, '');
      if (sanitized) {
        const like = `*${sanitized.replace(/\*/g, '')}*`;
        params.set(
          'or',
          `(handle.ilike.${like},name.ilike.${like},email.ilike.${like},id.ilike.${like})`,
        );
      }
    }
    let rows = [];
    try {
      rows = await sb(`users?${params.toString()}`);
    } catch (err) {
      handleMessageStoreError(err);
      return [];
    }
    let items = Array.isArray(rows) ? rows.map(presentUserForAdminRemote).filter(Boolean) : [];
    if (role) {
      const r = String(role).toLowerCase();
      items = items.filter((user) => {
        const userRole = (user.role || 'user').toLowerCase();
        return r === 'user' ? userRole === 'user' : userRole === r;
      });
    }
    if (query) {
      const lowerQuery = String(query).toLowerCase();
      items = items.filter((user) => {
        const fields = [user.handle, user.name, user.email, user.id]
          .filter(Boolean)
          .map((val) => String(val).toLowerCase());
        return fields.some((field) => field.includes(lowerQuery));
      });
    }
    items.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    const max = Math.min(Math.max(limit || 0, 0), 500);
    return max ? items.slice(0, max) : items;
  }

  async function adminListPostsRemote({ query, status, limit = 100 } = {}) {
    const params = new URLSearchParams();
    params.set('select', 'id,text,created_at,author_id,author_handle,author_name,author_avatar_url,status,attachments,comments');
    params.set('order', 'created_at.desc');
    params.set('limit', String(Math.min(Math.max(limit || 0, 1) * 3, 400)));
    if (query) {
      const sanitized = String(query).trim().replace(/[()]/g, '');
      if (sanitized) {
        const like = `*${sanitized.replace(/\*/g, '')}*`;
        params.set(
          'or',
          `(text.ilike.${like},author_handle.ilike.${like},author_name.ilike.${like})`,
        );
      }
    }
    let rows = [];
    try {
      rows = await sb(`posts?${params.toString()}`);
    } catch (err) {
      handleMessageStoreError(err);
      return [];
    }
    const filteredRows = (rows || []).filter((row) => (row.status || 'active') !== 'removed');
    const postIds = filteredRows.map((row) => row.id).filter(Boolean);
    const reportedPostIds = new Set();
    if (postIds.length) {
      try {
        const reportParams = new URLSearchParams();
        reportParams.set('select', 'post_id,status');
        reportParams.set('status', 'eq.open');
        reportParams.set('post_id', `in.(${postIds.map((id) => `"${id}"`).join(',')})`);
        const reportRows = await sb(`reports?${reportParams.toString()}`);
        reportRows
          .filter((row) => row?.post_id)
          .forEach((row) => reportedPostIds.add(row.post_id));
      } catch (err) {
        if (!isReportsTableMissingError(err)) handleMessageStoreError(err);
      }
    }
    let items = filteredRows.map((row) => {
      const baseStatus = row.status && row.status !== 'active' ? row.status : (reportedPostIds.has(row.id) ? 'reported' : 'active');
      return {
        id: row.id,
        text: row.text || '',
        createdAt: row.created_at || null,
        status: baseStatus,
        author: {
          id: row.author_id,
          handle: row.author_handle || null,
          name: row.author_name || null,
        },
      };
    });
    if (status) {
      const s = String(status).toLowerCase();
      items = items.filter((item) => (item.status || '').toLowerCase() === s);
    }
    if (query) {
      const lowerQuery = String(query).toLowerCase();
      items = items.filter((item) => {
        const fields = [item.text, item.author?.handle, item.author?.name]
          .filter(Boolean)
          .map((val) => String(val).toLowerCase());
        return fields.some((field) => field.includes(lowerQuery));
      });
    }
    items.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    const max = Math.min(Math.max(limit || 0, 0), 500);
    return max ? items.slice(0, max) : items;
  }

  async function setUserRoleRemote(userId, role) {
    if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
    const normalized = role ? String(role).toLowerCase() : 'user';
    const body = {
      role: normalized === 'superadmin' ? 'superadmin' : normalized === 'admin' ? 'admin' : 'user',
      is_superadmin: normalized === 'superadmin',
    };
    try {
      const rows = await sb(`users?id=eq.${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=representation' },
        body,
      });
      if (!rows || !rows.length) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
      return presentUserForAdminRemote(rows[0]);
    } catch (err) {
      handleMessageStoreError(err);
      throw err;
    }
  }

  async function logUserActionAdminRemote(entry = {}) {
    return recordUserActionRemote(entry);
  }

  return {
    mode: 'supabase',
    async ensureReady() {
      // Ensure global config row exists
      let cfg;
      let writeLockColumnSupported = true;
      try {
        cfg = await sb('config?select=id,allow_anon,registration_mode,invite_code_required,basic_posting_restricted&id=eq.global&limit=1');
      } catch (err) {
        if (isConfigColumnMissingError(err)) {
          writeLockColumnSupported = false;
          cfg = await sb('config?select=id,allow_anon,registration_mode,invite_code_required&id=eq.global&limit=1');
        } else {
          throw err;
        }
      }
      if (!cfg.length) {
        const body = {
          id: 'global',
          allow_anon: true,
          registration_mode: 'open',
          invite_code_required: false,
        };
        if (writeLockColumnSupported) body.basic_posting_restricted = false;
        await sb('config', {
          method: 'POST',
          headers: { Prefer: 'return=representation' },
          body,
        });
      } else {
        const existingCfg = cfg[0];
        const cfgPatch = {};
        if (existingCfg.registration_mode == null) cfgPatch.registration_mode = 'open';
        if (existingCfg.invite_code_required == null) cfgPatch.invite_code_required = false;
        if (writeLockColumnSupported && existingCfg.basic_posting_restricted == null) {
          cfgPatch.basic_posting_restricted = false;
        }
        if (Object.keys(cfgPatch).length) {
          await sb(`config?id=eq.${encodeURIComponent(existingCfg.id)}`, {
            method: 'PATCH',
            headers: { Prefer: 'return=minimal' },
            body: cfgPatch,
          });
        }
      }
      // Ensure seed user exists (developer default)
      const userRows = await sb('users?select=id,email,phone,avatar_url,role,is_superadmin&handle=eq.@looma_owner&limit=1');
      if (!userRows.length) {
        await sb('users', {
          method: 'POST',
          headers: { Prefer: 'return=representation' },
          body: {
            id: 'u1',
            handle: '@looma_owner',
            name: '성민 윤',
            email: 'owner@looma.local',
            phone: '010-0000-0000',
            avatar_url: null,
            password_hash: sha256('looma'),
            created_at: new Date().toISOString(),
            role: 'superadmin',
            is_superadmin: true,
          },
        });
      } else {
        const existing = userRows[0];
        const patch = {};
        if (!existing.email) patch.email = 'owner@looma.local';
        if (!existing.phone) patch.phone = '010-0000-0000';
        if (existing.avatar_url === undefined) patch.avatar_url = null;
        if (!existing.role) patch.role = 'superadmin';
        if (!existing.is_superadmin) patch.is_superadmin = true;
        if (Object.keys(patch).length) {
          await sb(`users?id=eq.${encodeURIComponent(existing.id)}`, {
            method: 'PATCH',
            headers: { Prefer: 'return=minimal' },
            body: patch,
          });
        }
      }
      await seedMessageChannels();
    },
    async getConfig() {
      const query = 'config?select=allow_anon,registration_mode,invite_code_required,basic_posting_restricted&id=eq.global&limit=1';
      try {
        const rows = await sb(query);
        const row = Array.isArray(rows) && rows[0] ? rows[0] : {};
        return presentSystemConfig({
          allowAnon: row.allow_anon ?? true,
          registrationMode: row.registration_mode || (row.invite_code_required ? 'invite' : 'open'),
          basicPostingRestricted: row.basic_posting_restricted ?? false,
        });
      } catch (err) {
        if (isConfigColumnMissingError(err)) {
          const rows = await sb('config?select=allow_anon&id=eq.global&limit=1');
          const row = Array.isArray(rows) && rows[0] ? rows[0] : {};
          return presentSystemConfig({ allowAnon: row.allow_anon ?? true, registrationMode: 'open', basicPostingRestricted: false });
        }
        handleMessageStoreError(err);
        throw err;
      }
    },
    async updateConfig(partial) {
      const body = {};
      if (typeof partial.allowAnon === 'boolean') body.allow_anon = partial.allowAnon;
      if (typeof partial.basicPostingRestricted === 'boolean') {
        body.basic_posting_restricted = partial.basicPostingRestricted;
      }
      let resolvedMode;
      if (typeof partial.registrationMode === 'string') {
        resolvedMode = partial.registrationMode === 'invite' ? 'invite' : 'open';
      }
      if (typeof partial.requiresReferralCode === 'boolean') {
        resolvedMode = partial.requiresReferralCode ? 'invite' : 'open';
      }
      if (resolvedMode) {
        body.registration_mode = resolvedMode;
        body.invite_code_required = resolvedMode === 'invite';
      }
      if (!Object.keys(body).length) {
        try {
          const rows = await sb(
            'config?select=allow_anon,registration_mode,invite_code_required,basic_posting_restricted&id=eq.global&limit=1',
          );
          const row = Array.isArray(rows) && rows[0] ? rows[0] : {};
          return presentSystemConfig({
            allowAnon: row.allow_anon ?? true,
            registrationMode: row.registration_mode || (row.invite_code_required ? 'invite' : 'open'),
            basicPostingRestricted: row.basic_posting_restricted ?? false,
          });
        } catch (err) {
          if (isConfigColumnMissingError(err)) {
            const rows = await sb('config?select=allow_anon&id=eq.global&limit=1');
            const row = Array.isArray(rows) && rows[0] ? rows[0] : {};
            return presentSystemConfig({
              allowAnon: row.allow_anon ?? true,
              registrationMode: 'open',
              basicPostingRestricted: false,
            });
          }
          handleMessageStoreError(err);
          throw err;
        }
      }
      try {
        const rows = await sb('config?id=eq.global', {
          method: 'PATCH',
          headers: { Prefer: 'return=representation' },
          body,
        });
        const row = Array.isArray(rows) && rows[0] ? rows[0] : {};
        return presentSystemConfig({
          allowAnon: row.allow_anon ?? body.allow_anon ?? true,
          registrationMode:
            row.registration_mode ||
            (row.invite_code_required ? 'invite' : resolvedMode || (body.invite_code_required ? 'invite' : 'open')),
          basicPostingRestricted: row.basic_posting_restricted ?? body.basic_posting_restricted ?? false,
        });
      } catch (err) {
        if (isConfigColumnMissingError(err)) {
          const fallback = {};
          if (body.allow_anon !== undefined) fallback.allow_anon = body.allow_anon;
          if (body.basic_posting_restricted !== undefined) {
            fallback.basic_posting_restricted = body.basic_posting_restricted;
          }
          if (!Object.keys(fallback).length) {
            const rows = await sb('config?select=allow_anon&id=eq.global&limit=1');
            const row = Array.isArray(rows) && rows[0] ? rows[0] : {};
            return presentSystemConfig({
              allowAnon: row.allow_anon ?? true,
              registrationMode: 'open',
              basicPostingRestricted: false,
            });
          }
          const rows = await sb('config?id=eq.global', {
            method: 'PATCH',
            headers: { Prefer: 'return=representation' },
            body: fallback,
          });
          const row = Array.isArray(rows) && rows[0] ? rows[0] : {};
          return presentSystemConfig({
            allowAnon: row.allow_anon ?? fallback.allow_anon ?? true,
            registrationMode: 'open',
            basicPostingRestricted: row.basic_posting_restricted ?? fallback.basic_posting_restricted ?? false,
          });
        }
        handleMessageStoreError(err);
        throw err;
      }
    },
    async listAnnouncements(opts) {
      return listAnnouncementsRemote(opts || {});
    },
    async getAnnouncement(id) {
      return getAnnouncementRemote(id);
    },
    async createAnnouncement(payload) {
      return createAnnouncementRemote(payload || {});
    },
    async updateAnnouncement(id, payload) {
      return updateAnnouncementRemote(id, payload || {});
    },
    async deleteAnnouncement(id) {
      return deleteAnnouncementRemote(id);
    },
    async listReferralCodes() {
      return listReferralCodesRemote();
    },
    async createReferralCode(payload) {
      return createReferralCodeRemote(payload || {});
    },
    async revokeReferralCode(code) {
      return revokeReferralCodeRemote(code);
    },
    async verifyReferralCode(code) {
      return verifyReferralCodeRemote(code);
    },
    async consumeReferralCode(code, meta) {
      return consumeReferralCodeRemote(code, meta || {});
    },
    async adminListReports(opts) {
      return adminListReportsRemote(opts || {});
    },
    async adminResolveReport(id, status) {
      return adminResolveReportRemote(id, status || 'closed');
    },
    async adminListUsers(opts) {
      return adminListUsersRemote(opts || {});
    },
    async adminListPosts(opts) {
      return adminListPostsRemote(opts || {});
    },
    async setUserRole(userId, role) {
      return setUserRoleRemote(userId, role);
    },
    async logUserAction(entry) {
      return logUserActionAdminRemote(entry || {});
    },
    async getSessionUser(sid) {
      if (!sid) return null;
      const sessions = await sb(`sessions?select=user_id&id=eq.${encodeURIComponent(sid)}&limit=1`);
      if (!sessions.length) return null;
      const userId = sessions[0].user_id;
      const rows = await sb(
        `users?select=id,handle,name,email,phone,avatar_url,created_at,status,deactivated_at,deleted_at,suspended_until,role,is_superadmin&id=eq.${encodeURIComponent(userId)}&limit=1`,
      );
      const user = rows[0];
      if (!user) return null;
      if ((user.status || 'active') !== 'active') return null;
      return publicUser(user);
    },
    async createSession(userId) {
      const existing = await fetchUserAuthById(userId);
      if (!existing) throw messageError('user-not-found', '사용자를 찾을 수 없습니다.');
      if (existing.status === 'deleted') throw messageError('account-deleted', '삭제된 계정입니다.');
      if (existing.status === 'deactivated') throw messageError('account-deactivated', '비활성화된 계정입니다.');
      if (existing.status === 'suspended') throw messageError('account-suspended', '정지된 계정입니다.');
      if (existing.status === 'banned') throw messageError('account-banned', '영구 정지된 계정입니다.');
      const sid = uid(16);
      await sb('sessions', {
        method: 'POST',
        headers: { Prefer: 'return=representation' },
        body: { id: sid, user_id: userId, created_at: new Date().toISOString() },
      });
      return sid;
    },
    async deleteSession(sid) {
      if (!sid) return;
      await sb(`sessions?id=eq.${encodeURIComponent(sid)}`, { method: 'DELETE' });
    },
    async findUserByHandle(handle) {
      if (!handle) return null;
      let normalized = String(handle || '').trim();
      if (!normalized) return null;
      if (!normalized.startsWith('@')) normalized = '@' + normalized;
      normalized = '@' + normalized.slice(1).toLowerCase();
      let rows = await sb(
        `users?select=id,handle,name,email,phone,avatar_url,password_hash,created_at,status,deactivated_at,deleted_at,suspended_until,role,is_superadmin&handle=eq.${encodeURIComponent(normalized)}&limit=1`,
      );
      if ((!rows || !rows.length) && normalized.startsWith('@')) {
        rows = await sb(
          `users?select=id,handle,name,email,phone,avatar_url,password_hash,created_at,status,deactivated_at,deleted_at,suspended_until,role,is_superadmin&handle=eq.${encodeURIComponent(
            normalized.slice(1),
          )}&limit=1`,
        );
      }
      if (!rows.length) return null;
      return {
        id: rows[0].id,
        handle: rows[0].handle,
        name: rows[0].name,
        email: rows[0].email,
        phone: rows[0].phone,
        avatarUrl: rows[0].avatar_url,
        passwordHash: rows[0].password_hash,
        createdAt: rows[0].created_at,
        status: rows[0].status || 'active',
        deactivatedAt: rows[0].deactivated_at || null,
        deletedAt: rows[0].deleted_at || null,
      };
    },
    async findUserByEmail(email) {
      if (!email) return null;
      const rows = await sb(
        `users?select=id,handle,name,email,phone,avatar_url,password_hash,created_at,status,deactivated_at,deleted_at,suspended_until,role,is_superadmin&email=eq.${encodeURIComponent(email)}&limit=1`,
      );
      if (!rows.length) return null;
      const row = rows[0];
      return {
        id: row.id,
        handle: row.handle,
        name: row.name,
        email: row.email,
        phone: row.phone,
        avatarUrl: row.avatar_url,
        passwordHash: row.password_hash,
        createdAt: row.created_at,
        status: row.status || 'active',
        deactivatedAt: row.deactivated_at || null,
        deletedAt: row.deleted_at || null,
      };
    },
    async findUserByPhone(phone) {
      if (!phone) return null;
      const rows = await sb(
        `users?select=id,handle,name,email,phone,avatar_url,password_hash,created_at,status,deactivated_at,deleted_at,suspended_until,role,is_superadmin&phone=eq.${encodeURIComponent(phone)}&limit=1`,
      );
      if (!rows.length) return null;
      const row = rows[0];
      return {
        id: row.id,
        handle: row.handle,
        name: row.name,
        email: row.email,
        phone: row.phone,
        avatarUrl: row.avatar_url,
        passwordHash: row.password_hash,
        createdAt: row.created_at,
        status: row.status || 'active',
        deactivatedAt: row.deactivated_at || null,
        deletedAt: row.deleted_at || null,
      };
    },
    async createUser({ email, phone, passwordHash, handle, name, avatarUrl }) {
      const payload = {
        id: 'u_' + uid(8),
        handle,
        name,
        email,
        phone,
        avatar_url: avatarUrl || null,
        password_hash: passwordHash,
        created_at: new Date().toISOString(),
        status: 'active',
        deactivated_at: null,
        deleted_at: null,
        suspended_until: null,
      };
      const rows = await sb('users', {
        method: 'POST',
        headers: { Prefer: 'return=representation' },
        body: payload,
      });
      const row = rows[0];
      return {
        id: row.id,
        handle: row.handle,
        name: row.name,
        email: row.email,
        phone: row.phone,
        avatarUrl: row.avatar_url,
        passwordHash: row.password_hash,
        createdAt: row.created_at,
        status: row.status || 'active',
        deactivatedAt: row.deactivated_at || null,
        deletedAt: row.deleted_at || null,
        suspendedUntil: row.suspended_until || null,
      };
    },
    async getPostById(postId) {
      if (!postId) return null;
      const rows = await sb(
        `posts?select=id,text,attachments,created_at,author_id,author_handle,author_name,author_avatar_url,comments(id,post_id,author_type,author_id,author_handle,author_name,author_avatar_url,text,created_at,guest_pw_hash)&id=eq.${encodeURIComponent(
          postId,
        )}&limit=1`,
      );
      if (!rows.length) return null;
      return mapPost(rows[0]);
    },
    async listPosts() {
      const rows = await sb(
        'posts?select=id,text,attachments,status,created_at,author_id,author_handle,author_name,author_avatar_url,comments(id,post_id,author_type,author_id,author_handle,author_name,author_avatar_url,text,created_at,guest_pw_hash)&order=created_at.desc&comments.order=created_at.asc',
      );
      const filteredRows = rows.filter((row) => (row.status || 'active') !== 'removed');
      const authorIds = new Set();
      filteredRows.forEach((row) => {
        if (row.author_id) authorIds.add(row.author_id);
        if (Array.isArray(row.comments)) {
          row.comments.forEach((comment) => {
            if (comment?.author_id) authorIds.add(comment.author_id);
          });
        }
      });
      const userMap = authorIds.size ? await loadUsersByIds(Array.from(authorIds)) : new Map();
      return filteredRows.map((row) => {
        const base = mapPost(row);
        const enrichedAuthor = base.author?.id ? userMap.get(base.author.id) : null;
        if (enrichedAuthor) {
          base.author = compactAuthor({
            id: enrichedAuthor.id,
            handle: enrichedAuthor.handle,
            name: enrichedAuthor.name,
            avatarUrl: enrichedAuthor.avatarUrl,
          });
        }
        base.comments = (base.comments || []).map((comment) => {
          const commentUser = comment?.author?.id ? userMap.get(comment.author.id) : null;
          if (commentUser) {
            return {
              ...comment,
              author: compactAuthor(commentUser),
            };
          }
          return comment;
        });
        return base;
      });
    },
    async createPost({ user, text, attachments }) {
      const normalizedAttachments = Array.isArray(attachments)
        ? attachments.map((att) => normalizeAttachmentForStore(att)).filter(Boolean)
        : [];
    const payload = {
      id: 'p_' + uid(6),
      author_id: user.id,
      author_handle: user.handle,
      author_name: user.name,
      author_avatar_url: user.avatarUrl || null,
      text: String(text || '').slice(0, 2000),
      created_at: new Date().toISOString(),
      attachments: normalizedAttachments,
      status: 'active',
    };
      const rows = await sb('posts', {
        method: 'POST',
        headers: { Prefer: 'return=representation' },
        body: payload,
      });
      return mapPost(rows[0]);
    },
    async updatePost(postId, { text, attachments }) {
      if (!postId) return null;
      const body = {};
      if (typeof text === 'string') body.text = String(text).slice(0, 2000);
      if (Array.isArray(attachments)) {
        body.attachments = attachments
          .map((att) => normalizeAttachmentForStore(att))
          .filter(Boolean);
      }
      if (!Object.keys(body).length) return this.getPostById(postId);
      const rows = await sb(`posts?id=eq.${encodeURIComponent(postId)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=representation' },
        body,
      });
      if (!rows.length) return null;
      return mapPost(rows[0]);
    },
    async deletePost(postId) {
      if (!postId) return false;
      await sb(`posts?id=eq.${encodeURIComponent(postId)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        body: { status: 'removed' },
      });
      return true;
    },
    async createComment({ postId, payload }) {
      const postRows = await sb(
        `posts?select=id,author_id,author_handle,author_name,author_avatar_url,text&limit=1&id=eq.${encodeURIComponent(postId)}`,
      );
      if (!Array.isArray(postRows) || !postRows.length) return null;
      const postRow = postRows[0];
      const body = {
        id: 'c_' + uid(6),
        post_id: postId,
        author_type: payload.authorType,
        text: String(payload.text || '').slice(0, 1000),
        created_at: new Date().toISOString(),
      };
      if (payload.authorType === 'user') {
        body.author_id = payload.user.id;
        body.author_handle = payload.user.handle;
        body.author_name = payload.user.name;
        body.author_avatar_url = payload.user.avatarUrl || null;
      } else if (payload.authorType === 'guest') {
        body.guest_pw_hash = payload.guestPwHash;
      }
      const rows = await sb('comments', {
        method: 'POST',
        headers: { Prefer: 'return=representation' },
        body,
      });
      const commentRow = rows[0];
      if (
        payload.authorType === 'user' &&
        postRow.author_id &&
        postRow.author_id !== payload.user.id
      ) {
        await createNotificationRemote({
          userId: postRow.author_id,
          type: 'comment',
          actorId: payload.user.id,
          postId,
          commentId: body.id,
          payload: { text: body.text },
        });
      }
      return mapComment(commentRow);
    },
    async getCommentById(commentId) {
      const rows = await sb(
        `comments?select=id,post_id,author_type,author_id,author_handle,author_name,author_avatar_url,text,created_at,guest_pw_hash&id=eq.${encodeURIComponent(
          commentId,
        )}&limit=1`,
      );
      if (!rows.length) return null;
      return { comment: mapComment(rows[0]) };
    },
    async updateComment(commentId, { text }) {
      const rows = await sb(`comments?id=eq.${encodeURIComponent(commentId)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=representation' },
        body: { text: String(text || '').slice(0, 1000) },
      });
      return mapComment(rows[0]);
    },
    async deleteComment(commentId) {
      await sb(`comments?id=eq.${encodeURIComponent(commentId)}`, { method: 'DELETE' });
      return true;
    },
    async voteOnPoll({ postId, pollId, optionId, userId, cid }) {
      if (!postId) throw Object.assign(new Error('postId required'), { code: 'post-required' });
      if (!pollId) throw Object.assign(new Error('pollId required'), { code: 'poll-required' });
      if (!optionId) throw Object.assign(new Error('optionId required'), { code: 'option-required' });
      const rows = await sb(
        `posts?select=id,attachments,author_id,author_handle,author_name,author_avatar_url,text,created_at&limit=1&id=eq.${encodeURIComponent(
          postId,
        )}`,
      );
      if (!rows.length) throw Object.assign(new Error('post not found'), { code: 'post-not-found' });
      const attachments = normalizeAttachmentsFromRow(rows[0].attachments);
      const poll = attachments.find((att) => att && att.type === 'poll' && att.pollId === pollId);
      if (!poll) throw Object.assign(new Error('poll not found'), { code: 'poll-not-found' });
      poll.voters ||= { users: {}, clients: {} };
      poll.voters.users ||= {};
      poll.voters.clients ||= {};
      const identity = userId
        ? { type: 'user', key: userId }
        : cid
        ? { type: 'client', key: cid }
        : null;
      if (!identity) throw Object.assign(new Error('identity required'), { code: 'identity-required' });
      const voterMap = identity.type === 'user' ? poll.voters.users : poll.voters.clients;
      if (voterMap[identity.key]) {
        throw Object.assign(new Error('already voted'), { code: 'already-voted' });
      }
      const option = (poll.options || []).find((opt) => opt.id === optionId);
      if (!option) throw Object.assign(new Error('option not found'), { code: 'option-not-found' });
      option.count = (Number(option.count) || 0) + 1;
      poll.totalVotes = (Number(poll.totalVotes) || 0) + 1;
      voterMap[identity.key] = optionId;

      const updatedRows = await sb(`posts?id=eq.${encodeURIComponent(postId)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=representation' },
        body: { attachments },
      });
      if (!updatedRows.length) throw Object.assign(new Error('post not found'), { code: 'post-not-found' });
      const updatedPost = mapPost(updatedRows[0]);
      const pollForClient = clonePollForClient(poll, {
        viewerUserId: userId || null,
        viewerCid: cid || null,
      });
      return { post: updatedPost, poll: pollForClient };
    },
    async getClient(cid) {
      if (!cid) return null;
      const rows = await sb(
        `clients?select=id,guest_used&id=eq.${encodeURIComponent(cid)}&limit=1`,
      );
      if (!rows.length) return null;
      return { guestUsed: !!rows[0].guest_used };
    },
    async markClientGuestUsed(cid) {
      if (!cid) return;
      const existing = await this.getClient(cid);
      if (existing) {
        await sb(`clients?id=eq.${encodeURIComponent(cid)}`, {
          method: 'PATCH',
          headers: { Prefer: 'return=representation' },
          body: { guest_used: true },
        });
      } else {
        await sb('clients', {
          method: 'POST',
          headers: { Prefer: 'return=representation' },
          body: { id: cid, guest_used: true, used_at: new Date().toISOString() },
        });
      }
    },
    async createReport({ postId, reason, detail, reporter }) {
      if (!postId) throw Object.assign(new Error('postId required'), { code: 'post-required' });
      if (!reason) throw Object.assign(new Error('reason required'), { code: 'reason-required' });
      if (!reporter || reporter.type !== 'user' || !reporter.user) {
        throw Object.assign(new Error('reporter invalid'), { code: 'reporter-required' });
      }
      const rows = await sb(
        `posts?select=id,text,author_id,author_handle,author_name&limit=1&id=eq.${encodeURIComponent(postId)}`,
      );
      if (!rows.length) throw Object.assign(new Error('post not found'), { code: 'post-not-found' });
      const postRow = rows[0];
      const nowIso = new Date().toISOString();
      const payload = {
        id: 'rpt_' + uid(8),
        type: 'post',
        status: 'open',
        post_id: postId,
        summary: String(postRow.text || '').slice(0, 160),
        reason: String(reason).trim(),
        detail: detail ? String(detail).trim() : null,
        reporter_type: 'user',
        reporter_user_id: reporter.user.id,
        reporter_handle: reporter.user.handle || null,
        reporter_name: reporter.user.name || null,
        target_type: 'post',
        target_id: postId,
        target_user_id: postRow.author_id || null,
        target_handle: postRow.author_handle || null,
        target_name: postRow.author_name || null,
        created_at: nowIso,
        updated_at: nowIso,
      };
      await sb('reports', {
        method: 'POST',
        headers: { Prefer: 'return=minimal' },
        body: payload,
      });
      return payload;
    },
    async getUserProfile(userId) {
      const row = await fetchUserRowById(userId);
      return row ? publicUser(row) : null;
    },
    async updateUserProfile(userId, updates) {
      return updateUserRow(userId, updates);
    },
    async getUserAuth(userId) {
      return fetchUserAuthById(userId);
    },
    async updateUserPassword(userId, newPasswordHash) {
      return updateUserPasswordRemote(userId, newPasswordHash);
    },
    async getUserProfileView(opts) {
      return getUserProfileViewRemote(opts || {});
    },
    async listFollowers(userId, opts) {
      return listFollowersRemote(userId, opts || {});
    },
    async listFollowing(userId, opts) {
      return listFollowingRemote(userId, opts || {});
    },
    async searchUsers(opts) {
      return searchUsersRemote(opts || {});
    },
    async listRandomUsers(opts) {
      return listRandomUsersRemote(opts || {});
    },
    async searchPosts(opts) {
      return searchPostsRemote(opts || {});
    },
    async searchTags(opts) {
      return searchTagsRemote(opts || {});
    },
    async getTrendingTags(opts) {
      return getTrendingTagsRemote(opts || {});
    },
    async listNotifications(userId, opts) {
      return listNotificationsRemote(userId, opts || {});
    },
    async countUnreadNotifications(userId) {
      return countUnreadNotificationsRemote(userId);
    },
    async listAccountActions(userId) {
      return listAccountActionsRemote(userId);
    },
    async getLatestAccountAction(userId) {
      return getLatestAccountActionRemote(userId);
    },
    async deactivateAccount(userId, payload) {
      return deactivateAccountRemote(userId, payload || {});
    },
    async deleteAccount(userId, payload) {
      return deleteAccountRemote(userId, payload || {});
    },
    async suspendAccount(userId, payload) {
      return suspendAccountRemote(userId, payload || {});
    },
    async banAccount(userId, payload) {
      return banAccountRemote(userId, payload || {});
    },
    async restoreAccount(userId, payload) {
      return restoreAccountRemote(userId, payload || {});
    },
    async invalidateUserSessions(userId) {
      return invalidateUserSessionsRemote(userId);
    },
    async followUser(followerId, targetId) {
      return followUserRemote(followerId, targetId);
    },
    async unfollowUser(followerId, targetId) {
      return unfollowUserRemote(followerId, targetId);
    },
    async listMessageChannels(userId) {
      if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
      let channelRows = [];
      try {
        channelRows = await sb(
          'message_channels?select=id,type,name,desc,tags,avatar,locked,created_at,created_by',
        );
      } catch (err) {
        handleMessageStoreError(err);
      }
      if (!Array.isArray(channelRows) || !channelRows.length) {
        return { channels: [], groups: [] };
      }
      const channelIds = channelRows.map((row) => row.id);
      const memberMap = await fetchMembersForChannels(channelIds);
      const counterpartIds = [];
      channelRows.forEach((row) => {
        if (!row || row.type !== 'dm') return;
        const members = memberMap.get(row.id) || [];
        members.forEach((memberId) => {
          if (memberId && memberId !== userId) counterpartIds.push(memberId);
        });
      });
      const userMap = await loadUsersByIds(counterpartIds);
      const lastMap = await fetchLastMessages(channelIds);

      const joined = [];
      const joinableGroups = [];
      channelRows.forEach((row) => {
        const meta = buildChannelMeta(row, {
          viewerId: userId,
          memberMap,
          userMap,
          lastMap,
          includeWhenNotJoined: row.type === 'group',
        });
        if (!meta) return;
        if (row.type === 'group' && !meta.joined) {
          joinableGroups.push(meta);
        } else {
          joined.push(meta);
        }
      });

      joined.sort((a, b) => {
        const at = new Date(a.lastMessageAt || a.createdAt || 0).getTime();
        const bt = new Date(b.lastMessageAt || b.createdAt || 0).getTime();
        return bt - at;
      });
      const squareIndex = joined.findIndex((c) => c.id === 'square');
      if (squareIndex > 0) {
        const [square] = joined.splice(squareIndex, 1);
        joined.unshift(square);
      }
      joinableGroups.sort((a, b) => (a.name || '').localeCompare(b.name || '', 'ko'));
      return { channels: joined, groups: joinableGroups };
    },
    async adminListMessageChannels() {
      return adminListMessageChannelsRemote();
    },
    async adminListChannelMessages(channelId, opts) {
      return adminListChannelMessagesRemote(channelId, opts || {});
    },
    async ensureDirectChannel({ viewerId, targetId }) {
      if (!viewerId || !targetId) {
        throw messageError('invalid-input', '대상 정보가 부족합니다.');
      }
      if (viewerId === targetId) {
        throw messageError('invalid-target', '자기 자신과의 채팅은 생성할 수 없습니다.');
      }
      const members = [viewerId, targetId].sort();
      const channelId = `dm_${members.join('_')}`;
      let channelRow = await loadChannelRow(channelId);
      if (!channelRow) {
        try {
          const rows = await sb('message_channels', {
            method: 'POST',
            headers: { Prefer: 'return=representation' },
            body: {
              id: channelId,
              type: 'dm',
              name: '',
              desc: '다이렉트 메시지',
              tags: [],
              avatar: null,
              locked: false,
              created_at: new Date().toISOString(),
              created_by: viewerId,
            },
          });
          channelRow = Array.isArray(rows) && rows[0] ? rows[0] : null;
        } catch (err) {
          handleMessageStoreError(err);
        }
      }
      if (!channelRow) {
        channelRow = await loadChannelRow(channelId);
        if (!channelRow) throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
      }
      await ensureMembership(channelId, viewerId);
      await ensureMembership(channelId, targetId);
      const memberIds = await fetchMembersForChannel(channelId);
      const memberMap = new Map([[channelId, memberIds]]);
      const userMap = await loadUsersByIds(memberIds.filter((id) => id && id !== viewerId));
      const lastMap = await fetchLastMessages([channelId]);
      const meta = buildChannelMeta(channelRow, {
        viewerId,
        memberMap,
        userMap,
        lastMap,
        includeWhenNotJoined: true,
      });
      if (!meta) throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
      return meta;
    },
    async joinMessageChannel(channelId, userId) {
      if (!channelId) throw messageError('channel-required', '채널 ID가 필요합니다.');
      if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
      const channelRow = await loadChannelRow(channelId);
      if (!channelRow) throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
      if (channelRow.type !== 'group') {
        throw messageError('invalid-channel', '그룹 채널만 참여할 수 있습니다.');
      }
      if (channelRow.locked) {
        throw messageError('access-denied', '이 그룹에는 참여할 수 없습니다.');
      }
      await ensureMembership(channelId, userId);
      const memberIds = await fetchMembersForChannel(channelId);
      const memberMap = new Map([[channelId, memberIds]]);
      const lastMap = await fetchLastMessages([channelId]);
      const meta = buildChannelMeta(channelRow, {
        viewerId: userId,
        memberMap,
        userMap: new Map(),
        lastMap,
        includeWhenNotJoined: true,
      });
      if (!meta) throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
      return meta;
    },
    async createMessageGroup({ userId, name, desc, tags }) {
      return createGroupChannel({ userId, name, desc, tags });
    },
    async leaveMessageChannel(channelId, userId) {
      return leaveGroupChannel(channelId, userId);
    },
    async listChannelMessages(channelId, { userId, limit = 50, after } = {}) {
      if (!channelId) throw messageError('channel-required', '채널 ID가 필요합니다.');
      if (!userId) throw messageError('auth-required', '인증이 필요합니다.');
      const channelRow = await loadChannelRow(channelId);
      if (!channelRow) throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
      let memberIds =
        channelRow.type === 'square' ? [] : await fetchMembersForChannel(channelId);
      if (
        channelRow.type !== 'square' &&
        (!Array.isArray(memberIds) || !memberIds.includes(userId))
      ) {
        throw messageError('access-denied', '채널에 접근할 수 없습니다.');
      }
      const params = new URLSearchParams();
      params.set('select', 'id,channel_id,author_id,text,created_at');
      params.set('channel_id', `eq.${channelId}`);
      params.set('order', 'created_at.desc');
      const capped = Number.isFinite(limit) ? Math.max(1, Math.min(Number(limit), 200)) : 50;
      if (after) {
        const parsed = Date.parse(after);
        if (Number.isFinite(parsed)) {
          params.set('created_at', `gt.${new Date(parsed).toISOString()}`);
        }
      }
      params.set('limit', String(capped));
      let rows = [];
      try {
        rows = await sb(`message_messages?${params.toString()}`);
      } catch (err) {
        handleMessageStoreError(err);
      }
      rows = Array.isArray(rows) ? rows.reverse() : [];

      const userIdsToLoad = new Set(rows.map((row) => row.author_id).filter(Boolean));
      if (channelRow.type === 'dm') {
        if (!memberIds.length) memberIds = await fetchMembersForChannel(channelId);
        memberIds.forEach((id) => {
          if (id && id !== userId) userIdsToLoad.add(id);
        });
      }
      const authorMap = await loadUsersByIds(Array.from(userIdsToLoad));
      const messages = rows.map((row) => mapMessageRow(row, authorMap));

      const memberMap = new Map([[channelId, memberIds]]);
      const lastMap = new Map();
      if (rows.length) {
        const lastRow = rows[rows.length - 1];
        lastMap.set(channelId, {
          id: lastRow.id,
          text: lastRow.text,
          createdAt: lastRow.created_at,
        });
      } else {
        const fetchedLast = await fetchLastMessages([channelId]);
        fetchedLast.forEach((value, key) => lastMap.set(key, value));
      }
      const meta = buildChannelMeta(channelRow, {
        viewerId: userId,
        memberMap,
        userMap: authorMap,
        lastMap,
        includeWhenNotJoined: true,
      });
      return { channel: meta, messages };
    },
    async appendChannelMessage(channelId, { user, text }) {
      if (!channelId) throw messageError('channel-required', '채널 ID가 필요합니다.');
      if (!user || !user.id) throw messageError('auth-required', '인증이 필요합니다.');
      const body = String(text || '').trim();
      if (!body) throw messageError('text-required', '메시지 내용을 입력해 주세요.');
      const channelRow = await loadChannelRow(channelId);
      if (!channelRow) throw messageError('channel-not-found', '채널을 찾을 수 없습니다.');
      if (channelRow.type === 'dm') {
        await ensureMembership(channelId, user.id);
      }
      const memberIds =
        channelRow.type === 'square' ? [] : await fetchMembersForChannel(channelId);
      if (
        channelRow.type !== 'square' &&
        (!Array.isArray(memberIds) || !memberIds.includes(user.id))
      ) {
        throw messageError('access-denied', '채널에 접근할 수 없습니다.');
      }
      const payload = {
        id: 'msg_' + uid(8),
        channel_id: channelId,
        author_id: user.id,
        text: body.slice(0, 2000),
        created_at: new Date().toISOString(),
      };
      let rows = null;
      try {
        rows = await sb('message_messages', {
          method: 'POST',
          headers: { Prefer: 'return=representation' },
          body: payload,
        });
      } catch (err) {
        handleMessageStoreError(err);
      }
      const inserted = Array.isArray(rows) && rows[0] ? rows[0] : payload;
      return {
        id: inserted.id,
        channelId: inserted.channel_id || channelId,
        text: inserted.text,
        createdAt: inserted.created_at,
        author: {
          id: user.id,
          handle: user.handle,
          name: user.name,
          avatarUrl: user.avatarUrl || null,
        },
      };
    },
    publicUser,
    presentPost(post, viewer) {
      return toClientPost(post, viewer);
    },
  };
}
