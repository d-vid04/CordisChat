// ============================================================================
// pq-chat — frontend logic
//
// Talks to the Rust core over Tauri's `invoke` / `event.listen` bridge.
// No bundler; we use the global `window.__TAURI__` exposed by
// `withGlobalTauri: true` in tauri.conf.json.
// ============================================================================

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const state = {
  identity:      null,
  ws_url:        'ws://127.0.0.1:8080',
  connected:     false,
  authenticated: false,
  servers:       new Map(),  // server_id -> ServerInfo (all known on relay)
  joined:        new Set(),  // server_ids we have membership in
  selected:      null,       // currently selected server_id
  messages:      new Map(),  // server_id -> Array<UiItem>
  members:       new Map(),  // server_id -> Map<user_id, MemberInfo>
  channelMeta:   new Map(),  // server_id -> { epoch, hasKey, name }
};

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

async function boot() {
  // Wire global listeners first so we don't miss any backend events.
  await wireEvents();

  // Have we got a persisted identity?
  const id = await invoke('cmd_load_identity').catch(showError);
  if (id) {
    state.identity = id;
    // Try to connect + login with stored credentials.
    showApp();
    setRelayLabel(state.ws_url);
    setCryptoMe(id.user_id);
    try {
      await invoke('cmd_connect', { url: state.ws_url });
      state.connected = true;
      await invoke('cmd_login');
      state.authenticated = true;
      await refreshServers();
    } catch (e) {
      toast(`could not log in: ${e}`, true);
    }
  } else {
    showOnboarding();
  }
}

// ---------------------------------------------------------------------------
// Onboarding
// ---------------------------------------------------------------------------

function showOnboarding() {
  $('onboarding').classList.remove('hidden');
  $('app').classList.add('hidden');
  $('ob-submit').addEventListener('click', onOnboardingSubmit);
  $('ob-name').focus();
}

async function onOnboardingSubmit() {
  const name = $('ob-name').value.trim();
  const url  = $('ob-url').value.trim();
  if (!name) { setObStatus('display name required', 'err'); return; }
  if (!url.startsWith('ws://') && !url.startsWith('wss://')) {
    setObStatus('relay must start with ws:// or wss://', 'err'); return;
  }

  const btn = $('ob-submit');
  btn.disabled = true;
  setObStatus('generating ML-KEM-768 and ML-DSA-65 keypairs…');

  try {
    state.ws_url = url;
    setObStatus('connecting to relay…');
    await invoke('cmd_connect', { url });
    state.connected = true;

    setObStatus('registering with relay…');
    const id = await invoke('cmd_register', { displayName: name });
    state.identity = id;
    state.authenticated = true;

    setObStatus('identity ready', 'ok');
    await new Promise(r => setTimeout(r, 250));

    $('onboarding').classList.add('hidden');
    showApp();
    setRelayLabel(url);
    setCryptoMe(id.user_id);
    await refreshServers();
  } catch (e) {
    setObStatus(`failed: ${e}`, 'err');
    btn.disabled = false;
  }
}

function setObStatus(text, cls = '') {
  const el = $('ob-status');
  el.textContent = text;
  el.className = `ob-status ${cls}`;
}

// ---------------------------------------------------------------------------
// App-level UI scaffolding
// ---------------------------------------------------------------------------

function showApp() {
  $('app').classList.remove('hidden');

  $('btn-new-server').addEventListener('click', () => openModal('modal-new-server', () => $('new-server-name').focus()));
  $('btn-discover').addEventListener('click', () => { openModal('modal-discover'); refreshDiscover(); });
  $('new-server-create').addEventListener('click', onCreateServer);
  $('discover-refresh').addEventListener('click', refreshDiscover);

  // Close-modal hooks (any [data-close] inside the overlay).
  $('modal-overlay').addEventListener('click', (ev) => {
    if (ev.target === $('modal-overlay') || ev.target.hasAttribute('data-close')) closeModal();
  });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') closeModal();
  });

  // Composer.
  const input = $('composer-input');
  const send  = $('composer-send');
  input.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && !ev.shiftKey) { ev.preventDefault(); doSend(); }
  });
  send.addEventListener('click', doSend);
}

// ---------------------------------------------------------------------------
// Tauri events
// ---------------------------------------------------------------------------

async function wireEvents() {
  await listen('connection_state', (e) => {
    const { state: cs, detail } = e.payload;
    if (cs === 'disconnected') {
      state.connected = false; state.authenticated = false;
      toast('disconnected from relay', true);
    }
    if (cs === 'connected' && detail) setRelayLabel(detail);
  });

  await listen('client_error', (e) => {
    toast(typeof e.payload === 'string' ? e.payload : 'error', true);
  });

  await listen('new_message', (e) => onNewMessage(e.payload));
  await listen('member_change', (e) => onMemberChange(e.payload));
  await listen('key_rotated', (e) => onKeyRotated(e.payload));
}

function onNewMessage(m) {
  const list = state.messages.get(m.server_id) || [];
  list.push({ kind: 'msg', ...m });
  state.messages.set(m.server_id, list);
  if (state.selected === m.server_id) {
    renderMessages();
  } else {
    // Subtle marker — pulse the server icon.
    pulseServer(m.server_id);
  }
}

function onMemberChange(m) {
  const list = state.messages.get(m.server_id) || [];
  list.push({
    kind: 'sys',
    text: m.kind === 'joined'
      ? `${m.display_name} joined — epoch ↑ ${m.epoch}`
      : `${m.display_name} left — epoch ↑ ${m.epoch}`,
    epoch: m.epoch,
  });
  state.messages.set(m.server_id, list);

  // Update member map.
  const mm = state.members.get(m.server_id) || new Map();
  if (m.kind === 'joined') {
    // We may not have the full MemberInfo here; refresh list.
    refreshMembers(m.server_id).catch(showError);
  } else {
    mm.delete(m.user_id);
    state.members.set(m.server_id, mm);
  }

  // Update epoch + clear hasKey (until KeyMaterial arrives).
  const meta = state.channelMeta.get(m.server_id) || {};
  meta.epoch  = m.epoch;
  meta.hasKey = false;
  state.channelMeta.set(m.server_id, meta);

  pulseServer(m.server_id);
  if (state.selected === m.server_id) {
    renderMessages();
    renderMembers();
    renderHeader();
    renderCrypto();
  }
  renderServerStrip(); // for the epoch badge
}

function onKeyRotated({ server_id, epoch }) {
  const meta = state.channelMeta.get(server_id) || {};
  meta.epoch  = epoch;
  meta.hasKey = true;
  state.channelMeta.set(server_id, meta);

  // Re-render any sealed messages at this epoch — but we don't store the
  // raw ciphertext on the JS side, so we can only do this for messages
  // received *after* the key arrives. Past sealed messages in this session
  // stay sealed for the UI even though the Rust core could in principle
  // retry. (Future improvement: a "retry decryption" command.)
  if (state.selected === server_id) { renderHeader(); renderCrypto(); }
}

// ---------------------------------------------------------------------------
// Server list / strip
// ---------------------------------------------------------------------------

async function refreshServers() {
  const list = await invoke('cmd_list_servers');
  state.servers.clear();
  for (const s of list) state.servers.set(s.server_id, s);

  // Update `joined` from intersection with whatever we already have memberships for.
  // We won't actually know server-side membership until we attempt to join — for
  // first-cut UX, we treat "joined" as servers we explicitly created or joined
  // this session (kept in state.joined).
  renderServerStrip();
}

function renderServerStrip() {
  const strip = $('server-strip');
  strip.innerHTML = '';
  for (const id of state.joined) {
    const s = state.servers.get(id);
    if (!s) continue;
    const meta = state.channelMeta.get(id) || { epoch: 0, hasKey: false };
    const el = document.createElement('div');
    el.className = 'server-icon' + (state.selected === id ? ' active' : '');
    el.style.background = bgForServer(id);
    el.innerHTML = `
      ${initials(s.name)}
      <span class="ep-badge">ε${meta.epoch}</span>
    `;
    el.title = `${s.name} — epoch ${meta.epoch}${meta.hasKey ? '' : ' (no key)'}`;
    el.addEventListener('click', () => selectServer(id));
    strip.appendChild(el);
  }
}

function pulseServer(id) {
  // Lightweight: find the rendered icon, add `.pulse`, remove after.
  const strip = $('server-strip');
  // Re-render server strip first to update epoch badge.
  renderServerStrip();
  const nodes = strip.querySelectorAll('.server-icon');
  // Pick by index in joined order.
  let idx = -1, i = 0;
  for (const sid of state.joined) { if (sid === id) { idx = i; break; } i++; }
  if (idx < 0) return;
  const node = nodes[idx];
  if (!node) return;
  node.classList.remove('pulse');
  // Force reflow to restart animation.
  // eslint-disable-next-line no-unused-expressions
  void node.offsetWidth;
  node.classList.add('pulse');
}

// ---------------------------------------------------------------------------
// Server selection & data load
// ---------------------------------------------------------------------------

async function selectServer(id) {
  state.selected = id;
  renderServerStrip();
  renderHeader();
  renderMessages();
  renderMembers();
  renderCrypto();

  // Refresh member list (definitive from relay) and history.
  await Promise.all([
    refreshMembers(id).catch(showError),
    refreshHistory(id).catch(showError),
  ]);
}

async function refreshMembers(id) {
  const list = await invoke('cmd_list_members', { serverId: id });
  const mm = new Map();
  for (const m of list) mm.set(m.user_id, m);
  state.members.set(id, mm);
  if (state.selected === id) renderMembers();
}

async function refreshHistory(id) {
  const items = await invoke('cmd_get_history', { serverId: id });
  // Prepend (history) to any messages we may have already received live.
  const existing = state.messages.get(id) || [];
  // Avoid duplicating: only keep history items whose message_id isn't already in `existing`.
  const seen = new Set(existing.filter(x => x.kind === 'msg').map(x => x.message_id));
  const fresh = items.filter(x => !seen.has(x.message_id)).map(x => ({ kind: 'msg', ...x }));
  state.messages.set(id, [...fresh, ...existing]);
  if (state.selected === id) renderMessages();
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

function renderHeader() {
  const id = state.selected;
  if (!id) {
    $('chat-title').textContent = 'no channel';
    $('chat-header-meta').innerHTML = '';
    return;
  }
  const s = state.servers.get(id);
  const meta = state.channelMeta.get(id) || { epoch: 0, hasKey: false };
  $('chat-title').textContent = s ? s.name : '—';
  const pill = meta.hasKey
    ? `<span class="pill live"><span class="dot"></span> live · ε${meta.epoch}</span>`
    : `<span class="pill"><span class="dot"></span> no key · ε${meta.epoch}</span>`;
  $('chat-header-meta').innerHTML = pill;
}

function renderMessages() {
  const id = state.selected;
  const wrap = $('messages');
  const empty = $('empty-state');

  if (!id) { empty.style.display = ''; wrap.querySelectorAll('.msg, .sysline').forEach(n => n.remove()); return; }
  empty.style.display = 'none';

  const items = state.messages.get(id) || [];
  wrap.querySelectorAll('.msg, .sysline').forEach(n => n.remove());

  let prevAuthor = null;
  let prevKind = null;
  for (const it of items) {
    if (it.kind === 'sys') {
      const row = document.createElement('div');
      row.className = 'sysline';
      row.innerHTML = `
        <div class="sysline-rule"></div>
        <div class="sysline-text">${escapeHtml(it.text)}</div>
        <div class="sysline-rule"></div>`;
      wrap.appendChild(row);
      prevAuthor = null; prevKind = 'sys';
      continue;
    }

    const compact = prevKind === 'msg' && prevAuthor === it.sender_id;
    const row = document.createElement('div');
    row.className = 'msg' + (compact ? ' compact' : '');

    const avatar = compact ? `<div></div>` : `
      <div class="avatar" style="background:${bgForUser(it.sender_id)}">
        ${escapeHtml(initials(it.sender_name))}
      </div>`;

    let badge = '';
    if (it.status === 'sealed') badge = `<span class="msg-badge sealed">sealed · ε${it.epoch}</span>`;
    else if (it.status === 'bad_sig') badge = `<span class="msg-badge bad">signature invalid</span>`;
    else if (it.status === 'decrypt_failed') badge = `<span class="msg-badge bad">decrypt failed</span>`;

    const text = (it.plaintext != null)
      ? `<div class="msg-text">${escapeHtml(it.plaintext)}</div>`
      : `<div class="msg-text sealed">encrypted under a key we don't hold</div>`;

    const meta = compact ? '' : `
      <div class="msg-meta">
        <span class="msg-author" style="color:${textForUser(it.sender_id)}">${escapeHtml(it.sender_name)}</span>
        <span class="msg-time">${fmtTime(it.timestamp)}</span>
        ${badge}
      </div>`;

    row.innerHTML = `${avatar}<div class="msg-body">${meta}${text}</div>`;
    wrap.appendChild(row);
    prevAuthor = it.sender_id; prevKind = 'msg';
  }

  wrap.scrollTop = wrap.scrollHeight;
}

function renderMembers() {
  const id = state.selected;
  const host = $('rail-members');
  host.innerHTML = '';
  if (!id) { $('rail-count').textContent = '0'; return; }
  const mm = state.members.get(id);
  if (!mm) { $('rail-count').textContent = '—'; return; }

  const me = state.identity?.user_id;
  const arr = [...mm.values()].sort((a, b) => {
    if (a.user_id === me) return -1;
    if (b.user_id === me) return 1;
    return a.display_name.localeCompare(b.display_name);
  });
  $('rail-count').textContent = String(arr.length);

  for (const m of arr) {
    const row = document.createElement('div');
    row.className = 'member' + (m.user_id === me ? ' you' : '');
    row.innerHTML = `
      <div class="member-avatar" style="background:${bgForUser(m.user_id)}">${escapeHtml(initials(m.display_name))}</div>
      <div class="member-body">
        <div class="member-name">${escapeHtml(m.display_name)}${m.user_id === me ? ' (you)' : ''}</div>
        <div class="member-fp">${shortId(m.user_id)} · ${kemFingerprint(m.kem_public_key)}</div>
      </div>`;
    host.appendChild(row);
  }
}

function renderCrypto() {
  const id = state.selected;
  const meta = id ? state.channelMeta.get(id) : null;
  if (!meta) {
    $('crypto-epoch').textContent = '—';
    $('crypto-epoch').className = 'crypto-val mono faint';
    $('crypto-key').textContent = '—';
    $('crypto-key').className = 'crypto-val mono faint';
  } else {
    $('crypto-epoch').textContent = `ε${meta.epoch}`;
    $('crypto-epoch').className = 'crypto-val mono live';
    $('crypto-key').textContent = meta.hasKey ? 'held · 32 B' : 'absent';
    $('crypto-key').className = 'crypto-val mono ' + (meta.hasKey ? 'live' : 'faint');
  }

  // Update composer enabled state.
  const canSend = !!(id && meta?.hasKey);
  $('composer-input').disabled = !canSend;
  $('composer-send').disabled  = !canSend;
  $('composer-input').placeholder = canSend
    ? `message #${state.servers.get(id)?.name ?? ''}`
    : (id ? 'waiting for group key…' : 'message #general');
}

function setRelayLabel(url) {
  $('crypto-relay').textContent = url.replace(/^wss?:\/\//, '');
  state.ws_url = url;
}
function setCryptoMe(uid) {
  $('crypto-me').textContent = shortId(uid);
}

// ---------------------------------------------------------------------------
// Composer send
// ---------------------------------------------------------------------------

async function doSend() {
  const id = state.selected;
  if (!id) return;
  const input = $('composer-input');
  const text  = input.value;
  if (!text.trim()) return;
  input.value = '';
  try {
    await invoke('cmd_send_message', { serverId: id, plaintext: text });
  } catch (e) {
    toast(`send failed: ${e}`, true);
    input.value = text;
  }
}

// ---------------------------------------------------------------------------
// Modal: create server
// ---------------------------------------------------------------------------

async function onCreateServer() {
  const name = $('new-server-name').value.trim();
  if (!name) return;
  try {
    const id = await invoke('cmd_create_server', { name });
    closeModal();
    $('new-server-name').value = '';

    // Insert into our local state.
    state.servers.set(id, { server_id: id, name, owner_id: state.identity.user_id, member_count: 1 });
    state.joined.add(id);
    const meta = { epoch: 0, hasKey: true, name };
    state.channelMeta.set(id, meta);
    const mm = new Map();
    mm.set(state.identity.user_id, {
      user_id:        state.identity.user_id,
      display_name:   state.identity.display_name,
      kem_public_key: b64ToBytes(state.identity.kem_pk_b64),
      sig_public_key: b64ToBytes(state.identity.sig_pk_b64),
    });
    state.members.set(id, mm);
    state.messages.set(id, []);

    renderServerStrip();
    selectServer(id);
  } catch (e) {
    toast(`create failed: ${e}`, true);
  }
}

// ---------------------------------------------------------------------------
// Modal: discover
// ---------------------------------------------------------------------------

async function refreshDiscover() {
  const host = $('discover-list');
  host.innerHTML = '<div class="discover-empty">loading…</div>';
  try {
    const list = await invoke('cmd_list_servers');
    state.servers.clear();
    for (const s of list) state.servers.set(s.server_id, s);

    host.innerHTML = '';
    if (!list.length) { host.innerHTML = '<div class="discover-empty">no servers yet — create one</div>'; return; }
    for (const s of list) {
      const row = document.createElement('div');
      row.className = 'discover-row';
      const joined = state.joined.has(s.server_id);
      row.innerHTML = `
        <div class="server-icon" style="background:${bgForServer(s.server_id)}">${initials(s.name)}</div>
        <div>
          <div class="discover-name">${escapeHtml(s.name)}</div>
          <div class="discover-meta">${shortId(s.server_id)} · ${s.member_count} member${s.member_count === 1 ? '' : 's'}</div>
        </div>
        <button class="discover-btn ${joined ? 'member' : ''}">${joined ? 'joined' : 'join'}</button>`;
      if (!joined) {
        row.querySelector('button').addEventListener('click', async (ev) => {
          ev.target.disabled = true;
          try {
            await invoke('cmd_join_server', { serverId: s.server_id });
            state.joined.add(s.server_id);
            const meta = state.channelMeta.get(s.server_id) || { epoch: 0, hasKey: false, name: s.name };
            meta.name = s.name;
            state.channelMeta.set(s.server_id, meta);
            state.messages.set(s.server_id, state.messages.get(s.server_id) || []);
            renderServerStrip();
            closeModal();
            selectServer(s.server_id);
          } catch (e) {
            toast(`join failed: ${e}`, true);
            ev.target.disabled = false;
          }
        });
      }
      host.appendChild(row);
    }
  } catch (e) {
    host.innerHTML = `<div class="discover-empty">${escapeHtml(String(e))}</div>`;
  }
}

// ---------------------------------------------------------------------------
// Modal plumbing
// ---------------------------------------------------------------------------

function openModal(id, after) {
  $('modal-overlay').classList.remove('hidden');
  document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
  $(id).classList.remove('hidden');
  if (after) after();
}
function closeModal() {
  $('modal-overlay').classList.add('hidden');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function showError(e) { toast(String(e), true); }

let toastTimer = null;
function toast(msg, isErr = false) {
  const t = $('toast');
  t.textContent = msg;
  t.className   = 'toast' + (isErr ? ' err' : '');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 4200);
}

function initials(name) {
  if (!name) return '?';
  const parts = name.trim().split(/\s+/).slice(0, 2);
  return parts.map(p => p[0]?.toUpperCase() ?? '').join('') || name[0].toUpperCase();
}

function shortId(uuid) {
  return String(uuid).split('-')[0] || String(uuid).slice(0, 8);
}

/** First 8 hex chars of FNV-1a 64 hash over the byte array — cheap deterministic
 *  fingerprint that gives users something stable to verify out-of-band. Real
 *  apps would surface SHA-256(pubkey)[:8] but Web Crypto needs async, and FNV
 *  is plenty for a visual identifier. */
function kemFingerprint(bytes) {
  // bytes is a JSON array of numbers from serde.
  if (!Array.isArray(bytes)) return '????????';
  let h = 0xcbf29ce484222325n;
  const p = 0x100000001b3n;
  for (const b of bytes) {
    h ^= BigInt(b & 0xff);
    h = (h * p) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0').slice(0, 8);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function fmtTime(iso) {
  const d = new Date(iso);
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  if (sameDay) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

/* Stable HSL color from a UUID — used for avatars and the "active server"
 * gradient. Hash via a small djb2 over the string. */
function hashStr(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}
function bgForUser(uid) {
  const h = hashStr(uid) % 360;
  return `linear-gradient(135deg, hsl(${h} 55% 42%), hsl(${(h + 30) % 360} 55% 32%))`;
}
function bgForServer(sid) {
  const h = hashStr(sid) % 360;
  return `linear-gradient(135deg, hsl(${h} 40% 22%), hsl(${(h + 40) % 360} 30% 14%))`;
}
function textForUser(uid) {
  const h = hashStr(uid) % 360;
  return `hsl(${h} 70% 72%)`;
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

boot();
