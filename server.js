'use strict';

/**
 * emesen — WebSocket relay sunucusu
 * -----------------------------------------------------------------
 * KİMLİK / HESAP KATMANI (kalıcı):
 *   data-store.json dosyasında yalnızca şunlar tutulur:
 *     - accounts: { id: { code, nickname, contacts:[id...], createdAt } }
 *     - pendingInvites: { code: { createdBy, createdAt } }
 *   Bu dosya sunucu çalışırken otomatik okunup yazılır — manuel commit
 *   GEREKMEZ. Render her yeniden deploy edildiğinde sıfırlanır (ephemeral
 *   disk); kalıcılığı garanti etmek istersen ileride harici bir DB'ye
 *   taşınabilir.
 *
 * MESAJ KATMANI (RAM-only, hiç diske yazılmaz):
 *   sessions ve offlineQueue yalnızca process belleğinde tutulur.
 *   Sunucu şifreli (ciphertext) içerikten başka bir şey görmez.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const WebSocket = require('ws');

const PORT = process.env.PORT || 10000;
const STORE_PATH = path.join(__dirname, 'data-store.json');
const PENDING_INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;   // kullanılmayan davet 7 günde düşer
const OFFLINE_MSG_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;  // güvenlik supabı

// ---------------------------------------------------------------
// Kalıcı hesap deposu
// ---------------------------------------------------------------
function loadStore() {
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf8');
    const data = JSON.parse(raw);
    return {
      accounts: data.accounts || {},
      pendingInvites: data.pendingInvites || {}
    };
  } catch {
    return { accounts: {}, pendingInvites: {} };
  }
}
let store = loadStore();
let saveScheduled = false;
function saveStore() {
  if (saveScheduled) return;
  saveScheduled = true;
  setImmediate(() => {
    saveScheduled = false;
    try {
      const tmp = STORE_PATH + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(store, null, 2));
      fs.renameSync(tmp, STORE_PATH);
    } catch (e) { console.error('store yazılamadı', e); }
  });
}

function codeToAccountId(code) {
  for (const [id, acc] of Object.entries(store.accounts)) if (acc.code === code) return id;
  return null;
}
function genId() { return crypto.randomBytes(9).toString('base64url'); }
function genCode() {
  let code;
  do { code = String(crypto.randomInt(0, 1000000)).padStart(6, '0'); }
  while (store.pendingInvites[code] || codeToAccountId(code));
  return code;
}
function genNickname() {
  const taken = new Set(Object.values(store.accounts).map(a => a.nickname));
  let nick;
  do { nick = 'emesen-' + String(crypto.randomInt(0, 100000)).padStart(5, '0'); }
  while (taken.has(nick));
  return nick;
}

// ---------------------------------------------------------------
// Çalışma zamanı (RAM) state
// ---------------------------------------------------------------
const sessions = new Map();       // accountId -> { ws, publicKey }
const offlineQueue = new Map();   // accountId -> Map(messageId -> {from, ciphertext, iv, ts})

function send(ws, payload) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify(payload)); } catch (_) {}
  }
}
function isOnline(id) { const s = sessions.get(id); return !!(s && s.ws && s.ws.readyState === WebSocket.OPEN); }
function publicUserInfo(id) {
  const acc = store.accounts[id];
  if (!acc) return null;
  const s = sessions.get(id);
  return { id, nickname: acc.nickname, online: isOnline(id), publicKey: s ? s.publicKey : null };
}
function contactListPayload(id) {
  const acc = store.accounts[id];
  if (!acc) return [];
  return acc.contacts.map(publicUserInfo).filter(Boolean);
}
function broadcastPresence(id, online) {
  const acc = store.accounts[id];
  if (!acc) return;
  for (const cid of acc.contacts) {
    const s = sessions.get(cid);
    if (s) send(s.ws, { type: 'presence', id, online });
  }
}
function deliverQueued(id) {
  const q = offlineQueue.get(id);
  const s = sessions.get(id);
  if (!q || !s) return;
  for (const [msgId, m] of q) {
    send(s.ws, { type: 'message', id: msgId, from: m.from, ciphertext: m.ciphertext, iv: m.iv, ts: m.ts });
  }
}

// ---------------------------------------------------------------
// HTTP + WebSocket
// ---------------------------------------------------------------
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(`emesen relay sunucusu calisiyor. Hesap sayisi: ${Object.keys(store.accounts).length}`);
});
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  let myId = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return send(ws, { type: 'error', message: 'geçersiz mesaj formatı' }); }
    if (!msg || typeof msg.type !== 'string') return;

    switch (msg.type) {
      case 'login': {
        const code = String(msg.code || '').trim();
        const publicKey = msg.publicKey;
        if (!/^\d{6}$/.test(code) || typeof publicKey !== 'object') {
          return send(ws, { type: 'error', message: 'geçersiz kod veya anahtar' });
        }

        let accountId = codeToAccountId(code);

        if (!accountId) {
          const invite = store.pendingInvites[code];
          const bootstrap = Object.keys(store.accounts).length === 0; // ilk hesap (kurucu)

          if (!invite && !bootstrap) {
            return send(ws, { type: 'error', message: 'geçersiz veya süresi dolmuş davet kodu' });
          }

          // Kalıcı yeni hesap oluştur — bu kod artık BU hesabın kalıcı giriş anahtarı
          accountId = genId();
          store.accounts[accountId] = {
            code,
            nickname: genNickname(),
            contacts: invite ? [invite.createdBy] : [],
            createdAt: Date.now()
          };
          if (invite) {
            const inviter = store.accounts[invite.createdBy];
            if (inviter && !inviter.contacts.includes(accountId)) inviter.contacts.push(accountId);
            delete store.pendingInvites[code];
          }
          saveStore();
        }

        myId = accountId;
        sessions.set(myId, { ws, publicKey });

        send(ws, {
          type: 'logged_in',
          id: myId,
          nickname: store.accounts[myId].nickname,
          contacts: contactListPayload(myId)
        });
        deliverQueued(myId);
        broadcastPresence(myId, true);

        // İlk katılımda: davet edenin ekranına yeni kişiyi anında düş
        for (const cid of store.accounts[myId].contacts) {
          const s = sessions.get(cid);
          if (s) send(s.ws, { type: 'contact_added', user: publicUserInfo(myId) });
        }
        break;
      }

      case 'generate_invite': {
        if (!myId) return;
        const code = genCode();
        store.pendingInvites[code] = { createdBy: myId, createdAt: Date.now() };
        saveStore();
        send(ws, { type: 'invite_created', code });
        break;
      }

      case 'get_public_key': {
        if (!myId || !msg.targetId) return;
        const info = publicUserInfo(msg.targetId);
        if (info && info.publicKey) send(ws, { type: 'public_key', id: info.id, publicKey: info.publicKey });
        break;
      }

      case 'message': {
        if (!myId) return;
        const { to, ciphertext, iv } = msg;
        if (!to || !ciphertext || !iv) return;
        const acc = store.accounts[myId];
        if (!acc || !acc.contacts.includes(to)) {
          return send(ws, { type: 'error', message: 'bu kullanıcıya mesaj gönderme yetkiniz yok' });
        }
        const msgId = genId();
        const ts = Date.now();
        const targetSession = sessions.get(to);
        const packet = { type: 'message', id: msgId, from: myId, ciphertext, iv, ts };

        if (targetSession && targetSession.ws.readyState === WebSocket.OPEN) {
          send(targetSession.ws, packet);
        } else {
          if (!offlineQueue.has(to)) offlineQueue.set(to, new Map());
          offlineQueue.get(to).set(msgId, { from: myId, ciphertext, iv, ts });
        }
        send(ws, { type: 'message_sent', id: msgId, to });
        break;
      }

      case 'read_receipt': {
        if (!myId) return;
        const { messageId, from } = msg;
        if (!messageId || !from) return;
        const q = offlineQueue.get(myId);
        if (q) q.delete(messageId);
        const senderSession = sessions.get(from);
        if (senderSession) send(senderSession.ws, { type: 'read_receipt', messageId, by: myId });
        break;
      }

      case 'ping':
        send(ws, { type: 'pong' });
        break;

      default:
        break;
    }
  });

  ws.on('close', () => {
    if (!myId) return;
    sessions.delete(myId);
    broadcastPresence(myId, false);
  });
  ws.on('error', () => { try { ws.close(); } catch (_) {} });
});

// Kullanılmamış davet kodlarını temizle (hesapların kendisi ASLA silinmez)
setInterval(() => {
  const cutoff = Date.now() - PENDING_INVITE_TTL_MS;
  let changed = false;
  for (const [code, inv] of Object.entries(store.pendingInvites)) {
    if (inv.createdAt < cutoff) { delete store.pendingInvites[code]; changed = true; }
  }
  if (changed) saveStore();

  const msgCutoff = Date.now() - OFFLINE_MSG_MAX_AGE_MS;
  for (const [uid, q] of offlineQueue) {
    for (const [mid, m] of q) if (m.ts < msgCutoff) q.delete(mid);
    if (q.size === 0) offlineQueue.delete(uid);
  }
}, 60 * 60 * 1000);

server.listen(PORT, () => {
  console.log(`emesen relay sunucusu :${PORT} — kayıtlı hesap sayısı: ${Object.keys(store.accounts).length}`);
});
