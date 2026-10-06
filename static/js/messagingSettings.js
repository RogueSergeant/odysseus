// Settings > Messaging: read-only Signal Desktop / WhatsApp backup sources.
//
// Loaded lazily the first time the panel opens (settings.js). Chat titles and
// sync errors originate outside Odysseus (other people name groups), so every
// dynamic string goes through textContent; nothing here uses innerHTML with
// server data.

import { styledConfirm, showToast } from './ui.js';

const API = '/api/messaging';
const SOURCE_LABEL = { whatsapp_backup: 'WhatsApp', signal_desktop: 'Signal' };

let _bound = false;
let _status = null;
let _chats = [];

function $(id) { return document.getElementById(id); }

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'style') node.style.cssText = value;
    else if (key === 'class') node.className = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child == null) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    credentials: 'same-origin',
    headers: opts.body ? { 'Content-Type': 'application/json' } : undefined,
    ...opts,
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
  return data;
}

function fmtDate(iso) {
  if (!iso) return 'never';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
}

function setMsg(id, text, isError = false) {
  const node = $(id);
  if (!node) return;
  node.textContent = text || '';
  node.style.color = isError ? 'var(--red, #c33)' : '';
}

function sourceRow(source) {
  const totals = source.totals || {};
  const stats = source.stats || {};
  const lines = [
    `${totals.chats || 0} chats, ${totals.messages || 0} messages`,
    `last sync ${fmtDate(source.last_sync_at)}`,
  ];
  if (stats.backup_taken_at) lines.push(`backup from ${fmtDate(stats.backup_taken_at)}`);
  const status = el('div', { style: 'font-size:11px;opacity:0.7;' }, lines.join(' · '));
  const error = source.last_error
    ? el('div', { style: 'font-size:11px;color:var(--red, #c33);margin-top:2px;' }, source.last_error)
    : null;
  const result = el('span', { style: 'font-size:11px;flex:1;' });

  const busy = async (btn, fn) => {
    btn.disabled = true;
    try { await fn(); } catch (e) { result.textContent = e.message; result.style.color = 'var(--red, #c33)'; }
    finally { btn.disabled = false; }
  };

  const testBtn = el('button', { class: 'admin-btn-sm' }, 'Test');
  testBtn.addEventListener('click', () => busy(testBtn, async () => {
    result.style.color = '';
    result.textContent = 'Testing…';
    const r = await api(`/sources/${encodeURIComponent(source.id)}/test`, { method: 'POST' });
    if (!r.ok) throw new Error(r.error || 'Test failed');
    result.textContent = `OK: ${r.chats} chats, ${r.messages} messages readable`
      + (r.backup_taken_at ? `, backup from ${fmtDate(r.backup_taken_at)}` : '');
  }));

  const syncBtn = el('button', { class: 'admin-btn-sm' }, 'Sync now');
  syncBtn.addEventListener('click', () => busy(syncBtn, async () => {
    result.style.color = '';
    result.textContent = 'Syncing…';
    const r = await api(`/sources/${encodeURIComponent(source.id)}/sync`, { method: 'POST' });
    if (r.status === 'error') throw new Error(r.error || 'Sync failed');
    if (r.status === 'busy') { result.textContent = 'A sync is already running.'; return; }
    result.textContent = `Synced: ${r.added || 0} new, ${r.removed || 0} removed`;
    await refresh();
  }));

  const toggle = el('button', { class: 'admin-btn-sm' }, source.enabled ? 'Pause' : 'Resume');
  toggle.addEventListener('click', () => busy(toggle, async () => {
    await api(`/sources/${encodeURIComponent(source.id)}`, {
      method: 'PUT', body: JSON.stringify({ enabled: !source.enabled }),
    });
    await refresh();
  }));

  const removeBtn = el('button', { class: 'admin-btn-delete' }, 'Remove');
  removeBtn.addEventListener('click', () => busy(removeBtn, async () => {
    const ok = await styledConfirm(
      `Remove ${source.name} and delete every message copied from it? Nothing on your phone or in Signal is touched.`,
      { confirmText: 'Remove', danger: true, title: 'Remove source' },
    );
    if (!ok) return;
    await api(`/sources/${encodeURIComponent(source.id)}`, { method: 'DELETE' });
    showToast(`${source.name} removed`);
    await refresh();
  }));

  const title = el('div', { style: 'font-weight:600;' },
    source.name + (source.enabled ? '' : ' (paused)'));
  return el('div', { class: 'admin-user-row', style: 'display:block;padding:8px 0;border-bottom:1px solid var(--border);' },
    title, status, error,
    el('div', { class: 'settings-row', style: 'gap:6px;margin-top:6px;align-items:center;' },
      result, testBtn, syncBtn, toggle, removeBtn));
}

function renderSources() {
  const sources = (_status && _status.sources) || [];
  const wa = sources.filter(s => s.kind === 'whatsapp_backup');
  const sig = sources.filter(s => s.kind === 'signal_desktop');
  const waBox = $('set-msg-wa-sources');
  const sigBox = $('set-msg-sig-sources');
  waBox.replaceChildren(...wa.map(sourceRow));
  sigBox.replaceChildren(...sig.map(sourceRow));
  // One source per app is the normal case; hide the add form once present.
  $('set-msg-wa-form').style.display = wa.length ? 'none' : '';
  $('set-msg-sig-form').style.display = sig.length ? 'none' : '';

  const totals = (_status && _status.totals) || {};
  $('set-msg-summary').textContent =
    `${totals.chats || 0} chats and ${totals.messages || 0} messages indexed. `
    + 'The "Messaging Sync" task refreshes every 15 minutes.';

  const env = [];
  env.push(_status.signal_mount_present
    ? `Signal folder mounted at ${_status.signal_mount}.`
    : `No Signal folder mounted at ${_status.signal_mount} (start Odysseus with docker/signal-desktop.yml).`);
  if (!_status.sqlcipher_available) env.push('The sqlcipher3 package is not installed, so Signal cannot be read yet.');
  $('set-msg-sig-env').textContent = env.join(' ');
}

function renderChats() {
  const box = $('set-msg-chats');
  const q = ($('set-msg-chat-filter').value || '').trim().toLowerCase();
  const rows = _chats.filter(c => !q || String(c.title || '').toLowerCase().includes(q));
  if (!rows.length) {
    box.replaceChildren(el('div', { class: 'admin-empty' }, _chats.length ? 'No chats match.' : 'No chats yet. Add a source and sync.'));
    return;
  }
  box.replaceChildren(...rows.map(chat => {
    const input = el('input', { type: 'checkbox' });
    input.checked = !chat.excluded;
    input.addEventListener('change', async () => {
      input.disabled = true;
      try {
        await api(`/chats/${encodeURIComponent(chat.id)}`, {
          method: 'PUT', body: JSON.stringify({ excluded: !input.checked }),
        });
        chat.excluded = !input.checked;
        if (chat.excluded) chat.message_count = 0;
        renderChats();
      } catch (e) {
        input.checked = !input.checked;
        showToast(e.message);
      } finally { input.disabled = false; }
    });
    const label = `${SOURCE_LABEL[chat.source_kind] || chat.source_kind}${chat.is_group ? ' group' : ''}`;
    return el('label', { class: 'settings-row', style: 'gap:8px;align-items:center;padding:3px 0;cursor:pointer;' },
      input,
      el('span', { style: 'flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;' }, chat.title || '(untitled)'),
      el('span', { style: 'font-size:11px;opacity:0.6;' },
        chat.excluded ? `${label} · excluded` : `${label} · ${chat.message_count || 0}`));
  }));
}

async function refresh() {
  try {
    _status = await api('/status');
    renderSources();
    const chats = await api('/chats');
    _chats = chats.chats || [];
    renderChats();
  } catch (e) {
    $('set-msg-summary').textContent = e.message;
  }
}

async function addSource(kind) {
  const isWa = kind === 'whatsapp_backup';
  const msgId = isWa ? 'set-msg-wa-msg' : 'set-msg-sig-msg';
  const btn = $(isWa ? 'set-msg-wa-add' : 'set-msg-sig-add');
  const body = isWa
    ? {
      kind, name: 'WhatsApp',
      secret: $('set-msg-wa-key').value,
      country_code: $('set-msg-wa-cc').value,
      path: $('set-msg-wa-path').value,
    }
    : {
      kind, name: 'Signal',
      secret: $('set-msg-sig-secret').value,
      path: $('set-msg-sig-path').value,
    };
  btn.disabled = true;
  setMsg(msgId, 'Saving…');
  try {
    const { source } = await api('/sources', { method: 'POST', body: JSON.stringify(body) });
    $(isWa ? 'set-msg-wa-key' : 'set-msg-sig-secret').value = '';
    setMsg(msgId, 'Saved. Testing…');
    const r = await api(`/sources/${encodeURIComponent(source.id)}/test`, { method: 'POST' });
    setMsg(msgId, r.ok ? 'Saved and readable. Syncing…' : `Saved, but: ${r.error}`, !r.ok);
    if (r.ok) await api(`/sources/${encodeURIComponent(source.id)}/sync`, { method: 'POST' });
    await refresh();
    setMsg(msgId, '');
  } catch (e) {
    setMsg(msgId, e.message, true);
  } finally {
    btn.disabled = false;
  }
}

export function openMessagingPanel() {
  if (!$('set-msg-summary')) return;
  if (!_bound) {
    _bound = true;
    $('set-msg-wa-add').addEventListener('click', () => addSource('whatsapp_backup'));
    $('set-msg-sig-add').addEventListener('click', () => addSource('signal_desktop'));
    $('set-msg-chat-filter').addEventListener('input', renderChats);
  }
  refresh().then(() => {
    const waPath = $('set-msg-wa-path');
    const sigPath = $('set-msg-sig-path');
    if (_status && waPath && !waPath.value) waPath.value = _status.whatsapp_inbox || '';
    if (_status && sigPath && !sigPath.value) sigPath.value = _status.signal_mount || '';
  });
}
