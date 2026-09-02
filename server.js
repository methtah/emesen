'use strict';

/**
 * emesen — WebSocket relay sunucusu
 * -----------------------------------------------------------------
 * Bu sunucu HİÇBİR VERİYİ DİSKE YAZMAZ. Tüm state (kullanıcılar,
 * davet kodları, çevrimdışı mesaj kuyruğu) yalnızca process RAM'inde
 * (Map/Set) tutulur. Sunucu, mesajların şifreli (ciphertext) halini
 * görür; şifre çözme işlemi yalnızca istemcide (tarayıcıda) yapılır.
 * Sunucu yeniden başladığında (deploy, restart, crash) tüm state sıfırlanır.
 */

const http = require('http');
const crypto = require('crypto');
const WebSocket = require('ws');

const PORT = process.env.PORT || 10000;
const INVITE_CODE_TTL_MS = 60 * 1000;      // davet kodu 60 sn'de bir yenilenir
const OFFLINE_MSG_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // güvenlik supabı: 7 gün sonra RAM'den temizle

// ---------------------------------------------------------------
// In-memory state
// ---------------------------------------------------------------
const clients = new Map();        // userId -> { ws, username, publicKey, contacts:Set<id>, inviteCode, inviteExpiresAt, inviteTimer }
const inviteCodeIndex = new Map(); // code(string) -> userId
const offlineQueue = new Map();    // userId -> Map(messageId -> {from, ciphertext, iv, ts})

function genId() {
  return crypto.randomBytes(9).toString('base64url');
}

function genInviteCode() {
  let code;
  do {
    code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  } while (inviteCodeIndex.has(code));
  return code;
}

function send(ws, payload) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify(payload)); } catch (_) { /* bağlantı kapanmış olabilir */ }
  }
}

function publicUserInfo(id) {
  const c = clients.get(id);
  if (!c) return null;
  return {
    id,
    username: c.username,
    online: !!(c.ws && c.ws.readyState === WebSocket.OPEN),
    publicKey: c.publicKey
  };
}

function contactListPayload(id) {
  const c = clients.get(id);
  if (!c) return [];
  return [...c.contacts].map(publicUserInfo).filter(Boolean);
}

function broadcastPresence(id, online) {
  const c = clients.get(id);
  if (!c) return;
  for (const contactId of c.contacts) {
    const contact = clients.get(contactId);
    if (contact) send(contact.ws, { type: 'presence', id, online });
  }
}

function rotateInviteCode(id) {
  const c = clients.get(id);
  if (!c) return;
  if (c.inviteCode) inviteCodeIndex.delete(c.inviteCode);
  const code = genInviteCode();
  const expiresAt = Date.now() + INVITE_CODE_TTL_MS;
  c.inviteCode = code;
  c.inviteExpiresAt = expiresAt;
  inviteCodeIndex.set(code, id);
  send(c.ws, { type: 'invite_code', code, expiresAt });
  clearTimeout(c.inviteTimer);
  c.inviteTimer = setTimeout(() => rotateInviteCode(id), INVITE_CODE_TTL_MS);
}

function deliverQueued(id) {
  const q = offlineQueue.get(id);
  const c = clients.get(id);
  if (!q || !c) return;
  for (const [msgId, m] of q) {
    send(c.ws, { type: 'message', id: msgId, from: m.from, ciphertext: m.ciphertext, iv: m.iv, ts: m.ts });
  }
}

// ---------------------------------------------------------------
// HTTP + WebSocket sunucusu
// ---------------------------------------------------------------
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('emesen relay sunucusu calisiyor (RAM-only, disk yok)');
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  let userId = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return send(ws, { type: 'error', message: 'geçersiz mesaj formatı' }); }
    if (!msg || typeof msg.type !== 'string') return;

    switch (msg.type) {
      case 'register': {
        if (typeof msg.username !== 'string' || !msg.username.trim() || typeof msg.publicKey !== 'object') {
          return send(ws, { type: 'error', message: 'kullanıcı adı ve genel anahtar zorunlu' });
        }
        userId = genId();
        clients.set(userId, {
          ws,
          username: msg.username.trim().slice(0, 32),
          publicKey: msg.publicKey,
          contacts: new Set(),
          inviteCode: null,
          inviteExpiresAt: null,
          inviteTimer: null
        });

        // Kayıt sırasında bir davet koduyla direkt katılım (opsiyonel)
        if (typeof msg.inviteCode === 'string' && msg.inviteCode.trim()) {
          const hostId = inviteCodeIndex.get(msg.inviteCode.trim());
          const host = hostId ? clients.get(hostId) : null;
          if (host && hostId !== userId) {
            host.contacts.add(userId);
            clients.get(userId).contacts.add(hostId);
            send(host.ws, { type: 'contact_added', user: publicUserInfo(userId) });
          } else {
            send(ws, { type: 'error', message: 'davet kodu geçersiz veya süresi dolmuş' });
          }
        }

        send(ws, { type: 'registered', id: userId, contacts: contactListPayload(userId) });
        rotateInviteCode(userId);
        deliverQueued(userId);
        broadcastPresence(userId, true);
        break;
      }

      case 'use_invite_code': {
        if (!userId) return;
        const code = String(msg.code || '').trim();
        const targetId = inviteCodeIndex.get(code);
        const self = clients.get(userId);
        if (!targetId || targetId === userId) {
          return send(ws, { type: 'error', message: 'davet kodu geçersiz veya süresi dolmuş' });
        }
        const target = clients.get(targetId);
        if (!target) return send(ws, { type: 'error', message: 'kullanıcı bulunamadı' });

        self.contacts.add(targetId);
        target.contacts.add(userId);
        send(ws, { type: 'contact_added', user: publicUserInfo(targetId) });
        send(target.ws, { type: 'contact_added', user: publicUserInfo(userId) });
        break;
      }

      case 'get_public_key': {
        if (!userId || !msg.targetId) return;
        const info = publicUserInfo(msg.targetId);
        if (info) send(ws, { type: 'public_key', id: info.id, publicKey: info.publicKey });
        break;
      }

      case 'message': {
        if (!userId) return;
        const { to, ciphertext, iv } = msg;
        if (!to || !ciphertext || !iv) return;
        const self = clients.get(userId);
        if (!self || !self.contacts.has(to)) {
          return send(ws, { type: 'error', message: 'bu kullanıcıya mesaj gönderme yetkiniz yok' });
        }
        const msgId = genId();
        const ts = Date.now();
        const target = clients.get(to);
        const packet = { type: 'message', id: msgId, from: userId, ciphertext, iv, ts };

        if (target && target.ws.readyState === WebSocket.OPEN) {
          send(target.ws, packet); // anında ilet
        } else {
          if (!offlineQueue.has(to)) offlineQueue.set(to, new Map());
          offlineQueue.get(to).set(msgId, { from: userId, ciphertext, iv, ts }); // yalnızca RAM
        }
        send(ws, { type: 'message_sent', id: msgId, to });
        break;
      }

      case 'read_receipt': {
        if (!userId) return;
        const { messageId, from } = msg;
        if (!messageId || !from) return;

        // Sunucu RAM'inden kalıcı olarak sil
        const q = offlineQueue.get(userId);
        if (q) q.delete(messageId);

        // Gönderene bildir: kendi ekranından/belleğinden de silsin
        const sender = clients.get(from);
        if (sender) send(sender.ws, { type: 'read_receipt', messageId, by: userId });
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
    if (!userId) return;
    const c = clients.get(userId);
    if (c) {
      clearTimeout(c.inviteTimer);
      if (c.inviteCode) inviteCodeIndex.delete(c.inviteCode);
      broadcastPresence(userId, false);
      clients.delete(userId); // kullanıcı verisi RAM'den tamamen kalkar
    }
  });

  ws.on('error', () => { try { ws.close(); } catch (_) {} });
});

// Güvenlik supabı: hiç okunmadan çok uzun süre bekleyen çevrimdışı mesajları temizle
setInterval(() => {
  const cutoff = Date.now() - OFFLINE_MSG_MAX_AGE_MS;
  for (const [uid, q] of offlineQueue) {
    for (const [mid, m] of q) if (m.ts < cutoff) q.delete(mid);
    if (q.size === 0) offlineQueue.delete(uid);
  }
}, 60 * 60 * 1000);

server.listen(PORT, () => {
  console.log(`emesen relay sunucusu :${PORT} — yalnızca RAM, veritabanı yok, disk yazımı yok`);
});
