import { useState, useRef, useEffect } from "react";

// ─── Crypto (AES-256-GCM + PBKDF2) ───────────────────────────────────────────
const ENC = new TextEncoder();
const DEC = new TextDecoder();

async function deriveKey(password, salt) {
  const raw = await crypto.subtle.importKey("raw", ENC.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

// Safe btoa for large buffers — avoids "Maximum call stack size exceeded"
// when spreading large Uint8Arrays into String.fromCharCode
function u8ToBase64(u8) {
  let binary = "";
  const chunk = 8192; // process in 8KB chunks
  for (let i = 0; i < u8.length; i += chunk) {
    binary += String.fromCharCode(...u8.subarray(i, i + chunk));
  }
  return btoa(binary);
}

async function aesEncrypt(text, key) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, ENC.encode(text));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv); out.set(new Uint8Array(ct), 12);
  return u8ToBase64(out); // safe for any size
}

async function aesDecrypt(b64, key) {
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const pt  = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, key, buf.slice(12));
  return DEC.decode(pt);
}

// ─── localStorage — only for tiny salt + verifier (a few hundred bytes) ───────
const K_SALT   = "pm_salt";
const K_VERIFY = "pm_verify";
const SENTINEL = "VAULT_OK_V2";

function getOrCreateSalt() {
  const s = localStorage.getItem(K_SALT);
  if (s) { try { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); } catch {} }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(K_SALT, u8ToBase64(salt));
  return salt;
}
async function saveVerifier(key) {
  localStorage.setItem(K_VERIFY, await aesEncrypt(SENTINEL, key));
}
async function verifyKey(key) {
  const enc = localStorage.getItem(K_VERIFY);
  if (!enc) return false;
  try { return (await aesDecrypt(enc, key)) === SENTINEL; } catch { return false; }
}

// ─── IndexedDB — vault storage (no size limit issues) ─────────────────────────
const DB_NAME    = "vaultDB";
const DB_VERSION = 1;
const STORE      = "vault";

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "id" });
      }
    };
    req.onsuccess = e => resolve(e.target.result);
    req.onerror   = e => reject(e.target.error);
  });
}

// Each vault item is stored individually by id — encrypted as one blob per item
async function idbSaveItem(item, key) {
  const db  = await openDB();
  const enc = await aesEncrypt(JSON.stringify(item), key);
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put({ id: item.id, data: enc });
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror    = e => { db.close(); reject(e.target.error); };
  });
}

async function idbDeleteItem(id) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(id);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror    = e => { db.close(); reject(e.target.error); };
  });
}

async function idbLoadAll(key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx      = db.transaction(STORE, "readonly");
    const req     = tx.objectStore(STORE).getAll();
    req.onsuccess = async e => {
      db.close();
      const rows = e.target.result;
      const items = [];
      for (const row of rows) {
        try {
          const plain = await aesDecrypt(row.data, key);
          items.push(JSON.parse(plain));
        } catch { /* skip corrupted rows */ }
      }
      // Sort by most recently updated
      items.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
      resolve(items);
    };
    req.onerror = e => { db.close(); reject(e.target.error); };
  });
}

async function idbClear() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).clear();
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror    = e => { db.close(); reject(e.target.error); };
  });
}

// Migrate any old localStorage vault to IndexedDB on first run
async function migrateFromLocalStorage(key) {
  const old = localStorage.getItem("pm_vault");
  if (!old) return;
  try {
    const plain = await aesDecrypt(old, key);
    const items = JSON.parse(plain);
    for (const item of items) await idbSaveItem(item, key);
    localStorage.removeItem("pm_vault");
    console.log("Migrated", items.length, "items from localStorage to IndexedDB");
  } catch { localStorage.removeItem("pm_vault"); }
}

// ─── Image compression ─────────────────────────────────────────────────────────
// Max 1200px, JPEG 0.75 — good balance of quality vs size
function compressImage(dataUrl) {
  return new Promise(resolve => {
    const img = new Image();
    img.onload = () => {
      const MAX = 1200;
      let { width: w, height: h } = img;
      if (w > MAX || h > MAX) {
        if (w > h) { h = Math.round(h * MAX / w); w = MAX; }
        else       { w = Math.round(w * MAX / h); h = MAX; }
      }
      const canvas = document.createElement("canvas");
      canvas.width = w; canvas.height = h;
      canvas.getContext("2d").drawImage(img, 0, 0, w, h);
      resolve(canvas.toDataURL("image/jpeg", 0.75));
    };
    img.onerror = () => resolve(dataUrl); // fallback: use original
    img.src = dataUrl;
  });
}

// ─── Backup (export/import) ────────────────────────────────────────────────────
async function exportBackup(vault, backupPw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key  = await deriveKey(backupPw, salt);
  const enc  = await aesEncrypt(JSON.stringify(vault), key);
  return JSON.stringify({ v: 2, salt: u8ToBase64(salt), data: enc, at: new Date().toISOString() });
}

async function importBackup(text, backupPw) {
  const b = JSON.parse(text);
  if (b.v !== 1 && b.v !== 2) throw new Error("Unknown backup version");
  const salt = Uint8Array.from(atob(b.salt), c => c.charCodeAt(0));
  const key  = await deriveKey(backupPw, salt);
  return JSON.parse(await aesDecrypt(b.data, key));
}

// ─── Icons ────────────────────────────────────────────────────────────────────
const Ic = ({ d, size = 20, color = "currentColor", sw = 1.7 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);
const I = {
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  lock:   "M19 11H5a2 2 0 00-2 2v7a2 2 0 002 2h14a2 2 0 002-2v-7a2 2 0 00-2-2zM7 11V7a5 5 0 0110 0v4",
  eye:    "M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z M12 9a3 3 0 100 6 3 3 0 000-6z",
  eyeOff: "M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24 M1 1l22 22",
  plus:   "M12 5v14M5 12h14",
  search: "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z",
  edit:   "M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7 M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z",
  trash:  "M3 6h18M8 6V4h8v2M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6",
  copy:   "M8 4H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-2 M8 4a2 2 0 012-2h4a2 2 0 012 2v0a2 2 0 01-2 2h-4a2 2 0 01-2-2z",
  check:  "M20 6L9 17l-5-5",
  x:      "M18 6L6 18M6 6l12 12",
  image:  "M21 15a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h4l2-3h4l2 3h4a2 2 0 012 2z M12 13a3 3 0 100-6 3 3 0 000 6z",
  key:    "M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4",
  globe:  "M12 2a10 10 0 100 20A10 10 0 0012 2z M2 12h20 M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z",
  note:   "M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z M14 2v6h6 M16 13H8m8 4H8m2-8H8",
  card:   "M1 4h22v16H1z M1 10h22",
  wifi:   "M5 12.55a11 11 0 0114.08 0 M1.42 9a16 16 0 0121.16 0 M8.53 16.11a6 6 0 016.95 0 M12 20h.01",
  back:   "M19 12H5m7-7l-7 7 7 7",
  logout: "M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4 M16 17l5-5-5-5 M21 12H9",
  spin:   "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15",
  dl:     "M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4 M7 10l5 5 5-5 M12 15V3",
  ul:     "M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4 M17 8l-5-5-5 5 M12 3v12",
  cog:    "M12 15a3 3 0 100-6 3 3 0 000 6z M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z",
  info:   "M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z M12 8h.01 M11 12h1v4h1",
  arr:    "M9 18l6-6-6-6",
  db:     "M12 2C6.48 2 2 4.24 2 7s4.48 5 10 5 10-2.24 10-5-4.48-5-10-5zM2 12c0 2.76 4.48 5 10 5s10-2.24 10-5M2 17c0 2.76 4.48 5 10 5s10-2.24 10-5",
};

// ─── Categories ───────────────────────────────────────────────────────────────
const CATS = [
  { id: "login", label: "Login", icon: I.key,   color: "#6366f1" },
  { id: "card",  label: "Card",  icon: I.card,  color: "#ec4899" },
  { id: "wifi",  label: "Wi-Fi", icon: I.wifi,  color: "#14b8a6" },
  { id: "note",  label: "Note",  icon: I.note,  color: "#f59e0b" },
  { id: "other", label: "Other", icon: I.globe, color: "#8b5cf6" },
];
const catColor = id => CATS.find(c => c.id === id)?.color || "#6366f1";
const catIcon  = id => CATS.find(c => c.id === id)?.icon  || I.key;
const catLabel = id => CATS.find(c => c.id === id)?.label || id;

// ─── Utilities ────────────────────────────────────────────────────────────────
function pwStrength(pw) {
  let s = 0;
  if (pw.length >= 8)        s++;
  if (pw.length >= 14)       s++;
  if (/[A-Z]/.test(pw))     s++;
  if (/[0-9]/.test(pw))     s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return s;
}
function genPw() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=";
  return Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => chars[b % chars.length]).join("");
}

// ─── CSS ──────────────────────────────────────────────────────────────────────
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a0f;--s1:#12121a;--s2:#1a1a26;--s3:#22223a;
  --bd:rgba(255,255,255,0.07);--tx:#f0f0ff;--mu:#6060a0;
  --ac:#7c3aed;--ac2:#a78bfa;--red:#ef4444;--grn:#22c55e;--ylw:#f59e0b;
  --r:16px;--rs:10px;
}
body{background:var(--bg);color:var(--tx);font-family:'Space Grotesk',sans-serif;-webkit-font-smoothing:antialiased}
.app{max-width:420px;min-height:100svh;margin:0 auto;background:var(--bg);display:flex;flex-direction:column;position:relative}

/* Auth */
.auth{min-height:100svh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 24px;
  background:radial-gradient(ellipse at 50% 0%,rgba(124,58,237,.22) 0%,transparent 60%),var(--bg)}
.auth-logo{width:76px;height:76px;background:linear-gradient(135deg,var(--ac),#6366f1);border-radius:24px;
  display:flex;align-items:center;justify-content:center;margin-bottom:20px;box-shadow:0 0 48px rgba(124,58,237,.4)}
.auth-title{font-size:28px;font-weight:700;letter-spacing:-.5px}
.auth-sub{color:var(--mu);font-size:14px;margin-top:6px;text-align:center;max-width:280px}
.auth-card{width:100%;background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:28px;margin-top:28px}

/* Inputs */
.lbl{font-size:11px;color:var(--mu);font-weight:600;letter-spacing:.5px;text-transform:uppercase;margin-bottom:7px;display:block}
.ig{margin-bottom:16px}
.iw{position:relative;display:flex;align-items:center}
.inp{width:100%;background:var(--s2);border:1px solid var(--bd);border-radius:var(--rs);color:var(--tx);
  font-family:'Space Grotesk',sans-serif;font-size:15px;padding:13px 44px 13px 15px;outline:none;transition:border-color .2s}
.inp:focus{border-color:var(--ac)} .inp::placeholder{color:var(--mu)}
textarea.inp{resize:none;min-height:80px;line-height:1.5;padding-right:15px}
.eye{position:absolute;right:12px;background:none;border:none;cursor:pointer;color:var(--mu);padding:0;display:flex;align-items:center}
.eye:hover{color:var(--tx)}
.sbar{display:flex;gap:4px;margin-top:7px}
.sseg{flex:1;height:3px;border-radius:99px;background:var(--s3);transition:background .3s}

/* Buttons */
.btn{width:100%;padding:14px;border:none;border-radius:var(--rs);font-family:'Space Grotesk',sans-serif;
  font-size:15px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:8px}
.btn-p{background:linear-gradient(135deg,var(--ac),#6366f1);color:#fff;box-shadow:0 4px 20px rgba(124,58,237,.3)}
.btn-p:hover{transform:translateY(-1px)}
.btn-p:active{transform:none}
.btn-p:disabled{opacity:.5;cursor:not-allowed;transform:none}
.btn-g{background:var(--s2);color:var(--tx);border:1px solid var(--bd)}
.btn-g:hover{border-color:var(--ac2);color:var(--ac2)}
.btn-d{background:rgba(239,68,68,.12);color:var(--red);border:1px solid rgba(239,68,68,.22)}
.btn-d:hover{background:rgba(239,68,68,.2)}

/* Alerts */
.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.22);color:var(--red);border-radius:var(--rs);padding:10px 14px;font-size:13px;margin-top:10px;text-align:center}
.ok-msg{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.22);color:var(--grn);border-radius:var(--rs);padding:10px 14px;font-size:13px;margin-top:10px;text-align:center}
.inf{background:rgba(124,58,237,.08);border:1px solid rgba(124,58,237,.18);border-radius:var(--rs);padding:14px 15px;font-size:13px;color:var(--mu);line-height:1.6;display:flex;gap:10px;align-items:flex-start}
.wrn{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);border-radius:var(--rs);padding:14px 15px;font-size:13px;color:var(--ylw);line-height:1.6;display:flex;gap:10px;align-items:flex-start}

/* Header */
.hdr{padding:52px 18px 14px;background:linear-gradient(to bottom,var(--s1) 60%,transparent);position:sticky;top:0;z-index:10;backdrop-filter:blur(20px)}
.hdr-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.hdr-logo{display:flex;align-items:center;gap:10px}
.hdr-logobox{width:34px;height:34px;background:linear-gradient(135deg,var(--ac),#6366f1);border-radius:10px;display:flex;align-items:center;justify-content:center}
.hdr-title{font-size:19px;font-weight:700;letter-spacing:-.3px}
.ibtn{width:36px;height:36px;background:var(--s2);border:1px solid var(--bd);border-radius:9px;
  display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--mu);transition:all .2s;flex-shrink:0}
.ibtn:hover{border-color:var(--ac2);color:var(--ac2)}

/* Search */
.sbox{position:relative}
.sico{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--mu);pointer-events:none}
.sinp{width:100%;background:var(--s2);border:1px solid var(--bd);border-radius:var(--rs);color:var(--tx);
  font-family:'Space Grotesk',sans-serif;font-size:14px;padding:11px 15px 11px 38px;outline:none;transition:border-color .2s}
.sinp:focus{border-color:var(--ac)} .sinp::placeholder{color:var(--mu)}

/* Pills */
.pills{display:flex;gap:7px;padding:10px 18px;overflow-x:auto;-webkit-overflow-scrolling:touch}
.pills::-webkit-scrollbar{display:none}
.pill{flex-shrink:0;display:flex;align-items:center;gap:5px;padding:7px 13px;border-radius:99px;
  background:var(--s2);border:1px solid var(--bd);font-size:13px;font-weight:500;cursor:pointer;
  transition:all .2s;color:var(--mu);white-space:nowrap;font-family:'Space Grotesk',sans-serif}

/* Vault list */
.vlist{flex:1;padding:0 18px 100px;overflow-y:auto}
.slbl{font-size:11px;color:var(--mu);font-weight:600;letter-spacing:1px;text-transform:uppercase;margin:14px 0 8px}
.vitem{display:flex;align-items:center;gap:13px;padding:13px 15px;background:var(--s1);
  border:1px solid var(--bd);border-radius:var(--r);margin-bottom:9px;cursor:pointer;transition:all .2s;position:relative;overflow:hidden}
.vitem:hover{border-color:rgba(255,255,255,.12);transform:translateX(2px)}
.vico{width:42px;height:42px;flex-shrink:0;border-radius:12px;display:flex;align-items:center;justify-content:center;overflow:hidden}
.vico img{width:100%;height:100%;object-fit:cover}
.vinf{flex:1;min-width:0}
.vname{font-size:15px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vsub{font-size:12px;color:var(--mu);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* Empty */
.empty{display:flex;flex-direction:column;align-items:center;padding:60px 20px;text-align:center;color:var(--mu)}
.empty svg{opacity:.3;margin-bottom:14px}

/* FAB pair */
.fab-wrap{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);width:100%;max-width:420px;
  display:flex;justify-content:space-between;padding:0 18px;pointer-events:none;z-index:20}
.fab{width:54px;height:54px;border:none;border-radius:16px;display:flex;align-items:center;justify-content:center;
  cursor:pointer;color:#fff;transition:all .2s;pointer-events:all;flex-shrink:0}
.fab-add{background:linear-gradient(135deg,var(--ac),#6366f1);box-shadow:0 6px 24px rgba(124,58,237,.5)}
.fab-add:hover{transform:translateY(-2px) scale(1.05)}
.fab-add:active{transform:scale(.97)}
.fab-set{background:var(--s2);border:1px solid var(--bd);box-shadow:0 4px 16px rgba(0,0,0,.4)}
.fab-set:hover{border-color:var(--ac2);transform:translateY(-2px)}
.fab-set:active{transform:scale(.97)}
.fab-set.on{background:rgba(124,58,237,.2);border-color:var(--ac2)}

/* Modal */
.ov{position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(6px);z-index:50;
  display:flex;align-items:flex-end;justify-content:center;animation:fi .2s ease}
@keyframes fi{from{opacity:0}to{opacity:1}}
.mdl{width:100%;max-width:420px;background:var(--s1);border-radius:var(--r) var(--r) 0 0;
  border:1px solid var(--bd);border-bottom:none;max-height:92svh;overflow-y:auto;
  animation:su .28s cubic-bezier(.34,1.56,.64,1)}
@keyframes su{from{transform:translateY(100%)}to{transform:translateY(0)}}
.mhdl{width:34px;height:4px;background:var(--s3);border-radius:99px;margin:11px auto 0}
.mhdr{display:flex;align-items:center;justify-content:space-between;padding:14px 18px 12px;border-bottom:1px solid var(--bd)}
.mtit{font-size:17px;font-weight:700}
.mbdy{padding:18px}

/* Detail */
.dhero{display:flex;align-items:center;gap:15px;padding:16px 18px 18px;border-bottom:1px solid var(--bd)}
.dico{width:54px;height:54px;border-radius:15px;display:flex;align-items:center;justify-content:center;overflow:hidden;flex-shrink:0}
.dico img{width:100%;height:100%;object-fit:cover}
.dtit{font-size:19px;font-weight:700}
.dcat{font-size:12px;color:var(--mu);margin-top:3px}
.frow{padding:13px 18px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:10px}
.flbl{font-size:10px;color:var(--mu);text-transform:uppercase;letter-spacing:.6px;font-weight:700;min-width:68px;flex-shrink:0}
.fval{flex:1;font-size:14px;font-family:'JetBrains Mono',monospace;word-break:break-all;color:var(--tx);line-height:1.4}
.ficb{width:30px;height:30px;background:var(--s2);border:1px solid var(--bd);border-radius:8px;
  display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--mu);transition:all .15s;flex-shrink:0}
.ficb:hover{color:var(--ac2);border-color:var(--ac2)}
.igrid{padding:14px 18px;display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.ithumb{aspect-ratio:1;border-radius:10px;overflow:hidden;background:var(--s2);cursor:pointer}
.ithumb img{width:100%;height:100%;object-fit:cover}
.arow{padding:14px 18px;display:flex;gap:9px}

/* Form */
.fsec{margin-bottom:18px}
.fsec-t{font-size:11px;color:var(--mu);font-weight:700;letter-spacing:.8px;text-transform:uppercase;margin-bottom:9px}
.upz{border:2px dashed var(--bd);border-radius:var(--rs);padding:18px;text-align:center;cursor:pointer;
  transition:all .2s;color:var(--mu);font-size:13px}
.upz:hover{border-color:var(--ac);color:var(--ac2)}
.ipgrid{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.ipbox{width:68px;height:68px;border-radius:10px;overflow:hidden;position:relative;background:var(--s2)}
.ipbox img{width:100%;height:100%;object-fit:cover}
.ipdel{position:absolute;top:3px;right:3px;width:17px;height:17px;background:rgba(239,68,68,.9);
  border-radius:99px;display:flex;align-items:center;justify-content:center;cursor:pointer}
.gbtn{display:flex;align-items:center;gap:6px;background:var(--s3);border:1px solid var(--bd);
  color:var(--ac2);border-radius:8px;padding:8px 12px;font-size:13px;font-weight:500;cursor:pointer;
  transition:all .2s;margin-top:8px;font-family:'Space Grotesk',sans-serif;white-space:nowrap;flex-shrink:0}
.gbtn:hover{border-color:var(--ac2)}
.prow{display:flex;align-items:flex-start;gap:8px} .prow .iw{flex:1}

/* Settings */
.spage{flex:1;overflow-y:auto;padding:0 18px 100px}
.spage-title{font-size:22px;font-weight:700;letter-spacing:-.4px;padding:52px 0 4px}
.shead{font-size:11px;color:var(--mu);font-weight:700;letter-spacing:1px;text-transform:uppercase;margin:22px 0 9px}
.sitem{display:flex;align-items:center;gap:13px;padding:15px;background:var(--s1);border:1px solid var(--bd);
  border-radius:var(--r);margin-bottom:9px;cursor:pointer;transition:all .2s}
.sitem:hover{border-color:rgba(255,255,255,.14)}
.sicobox{width:40px;height:40px;border-radius:12px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.slabel{font-size:15px;font-weight:600}
.ssub{font-size:12px;color:var(--mu);margin-top:2px}

/* Storage badge */
.badge{display:inline-flex;align-items:center;gap:5px;background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.2);
  border-radius:99px;padding:4px 10px;font-size:12px;color:var(--grn);font-weight:600;margin-top:6px}

/* Toast */
.toast{position:fixed;bottom:100px;left:50%;transform:translateX(-50%);background:var(--s2);border:1px solid var(--bd);
  border-radius:99px;padding:9px 18px;font-size:13px;font-weight:500;display:flex;align-items:center;gap:7px;
  z-index:200;box-shadow:0 4px 20px rgba(0,0,0,.5);white-space:nowrap;
  animation:tin .2s ease,tout .3s ease 1.7s forwards;pointer-events:none}
@keyframes tin{from{opacity:0;transform:translateX(-50%) translateY(10px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}
@keyframes tout{from{opacity:1}to{opacity:0}}

/* Loading screen */
.loading{min-height:100svh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;color:var(--mu)}
.spinner{width:36px;height:36px;border:3px solid var(--s3);border-top-color:var(--ac);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* Lightbox */
.lb{position:fixed;inset:0;z-index:300;background:rgba(0,0,0,.96);display:flex;align-items:center;justify-content:center;cursor:pointer;animation:fi .15s ease}
.lb img{max-width:100%;max-height:90svh;border-radius:8px}

::-webkit-scrollbar{width:3px} ::-webkit-scrollbar-track{background:transparent} ::-webkit-scrollbar-thumb{background:var(--s3);border-radius:99px}
`;

// ─── Shared small components ──────────────────────────────────────────────────
function StrBar({ pw }) {
  const s    = pwStrength(pw);
  const cols = ["#ef4444","#f97316","#eab308","#84cc16","#22c55e"];
  return <div className="sbar">{[0,1,2,3,4].map(i=><div key={i} className="sseg" style={{background:i<s?cols[Math.min(s-1,4)]:undefined}}/>)}</div>;
}

function PwInp({ value, onChange, placeholder="Password", strength=false }) {
  const [show, setShow] = useState(false);
  return <>
    <div className="iw">
      <input className="inp" type={show?"text":"password"} value={value}
        onChange={e=>onChange(e.target.value)} placeholder={placeholder}/>
      <button className="eye" type="button" onClick={()=>setShow(v=>!v)}>
        <Ic d={show?I.eyeOff:I.eye} size={17}/>
      </button>
    </div>
    {strength && value && <StrBar pw={value}/>}
  </>;
}

function Toast({ msg, type="ok" }) {
  const color = type==="error" ? "var(--red)" : "var(--grn)";
  const icon  = type==="error" ? I.x : I.check;
  return <div className="toast"><Ic d={icon} size={15} color={color}/><span style={{color}}>{msg}</span></div>;
}

// ─── Auth Screen ──────────────────────────────────────────────────────────────
function AuthScreen({ onAuth }) {
  const isNew = !localStorage.getItem(K_VERIFY);
  const [pw,   setPw]   = useState("");
  const [pw2,  setPw2]  = useState("");
  const [err,  setErr]  = useState("");
  const [busy, setBusy] = useState(false);

  async function submit() {
    setErr(""); setBusy(true);
    try {
      const salt = getOrCreateSalt();
      const key  = await deriveKey(pw, salt);
      if (isNew) {
        if (pw.length < 6) { setErr("Password must be at least 6 characters."); setBusy(false); return; }
        if (pw !== pw2)    { setErr("Passwords don't match."); setBusy(false); return; }
        await saveVerifier(key);
        await onAuth(key);
      } else {
        const ok = await verifyKey(key);
        if (!ok) { setErr("Wrong master password. Try again."); setBusy(false); return; }
        await onAuth(key);
      }
    } catch(e) { setErr("Error: " + e.message); }
    setBusy(false);
  }

  return (
    <div className="auth">
      <div className="auth-logo"><Ic d={I.shield} size={34} color="#fff" sw={2}/></div>
      <div className="auth-title">Vault</div>
      <div className="auth-sub">{isNew?"Create a master password to protect your vault":"Enter your master password to unlock"}</div>
      <div className="auth-card">
        <div className="ig"><label className="lbl">Master Password</label>
          <PwInp value={pw} onChange={setPw} placeholder="Master password" strength={isNew}/></div>
        {isNew && <div className="ig"><label className="lbl">Confirm Password</label>
          <PwInp value={pw2} onChange={setPw2} placeholder="Confirm password"/></div>}
        {err && <div className="err">{err}</div>}
        <button className="btn btn-p" style={{marginTop:18}} onClick={submit} disabled={busy}>
          {busy?"Working…":isNew?"Create Vault":"Unlock Vault"}
        </button>
        {!isNew && (
          <div style={{marginTop:14,fontSize:12,color:"var(--mu)",textAlign:"center",lineHeight:1.5}}>
            Powered by IndexedDB — no storage limits on images
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Export Modal ─────────────────────────────────────────────────────────────
function ExportModal({ vault, onClose, toast }) {
  const [pw,   setPw]   = useState("");
  const [pw2,  setPw2]  = useState("");
  const [err,  setErr]  = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function go() {
    setErr("");
    if (pw.length < 4) { setErr("Backup password must be at least 4 characters."); return; }
    if (pw !== pw2)    { setErr("Passwords don't match."); return; }
    setBusy(true);
    try {
      const json = await exportBackup(vault, pw);
      const url  = URL.createObjectURL(new Blob([json], {type:"application/json"}));
      const a    = Object.assign(document.createElement("a"), {
        href: url, download: `vault-backup-${new Date().toISOString().slice(0,10)}.json`
      });
      a.click(); URL.revokeObjectURL(url);
      setDone(true); toast("Backup downloaded!");
    } catch { setErr("Export failed. Try again."); }
    setBusy(false);
  }

  return (
    <div className="ov" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="mdl">
        <div className="mhdl"/>
        <div className="mhdr">
          <button className="ibtn" onClick={onClose}><Ic d={I.x} size={17}/></button>
          <div className="mtit">Export Backup</div>
          <div style={{width:36}}/>
        </div>
        <div className="mbdy">
          <div className="inf" style={{marginBottom:16}}>
            <Ic d={I.info} size={16} color="var(--ac2)" sw={2} style={{flexShrink:0,marginTop:1}}/>
            <div>Creates an encrypted <b style={{color:"var(--tx)"}}>.json</b> file protected by a backup password. Save it to Google Drive, WhatsApp, or email.</div>
          </div>
          <div className="ig"><label className="lbl">Backup Password</label>
            <PwInp value={pw} onChange={setPw} placeholder="Choose a backup password" strength/></div>
          <div className="ig"><label className="lbl">Confirm Backup Password</label>
            <PwInp value={pw2} onChange={setPw2} placeholder="Confirm backup password"/></div>
          {err && <div className="err">{err}</div>}
          {done && <div className="ok-msg">✓ File downloaded! Store it somewhere safe.</div>}
          <button className="btn btn-p" style={{marginTop:10}} onClick={go} disabled={busy||done}>
            <Ic d={I.dl} size={17}/>{busy?"Encrypting…":done?"Downloaded ✓":"Download Backup File"}
          </button>
          <button className="btn btn-g" style={{marginTop:9}} onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

// ─── Import Modal ─────────────────────────────────────────────────────────────
function ImportModal({ current, onImport, onClose, toast }) {
  const [pw,      setPw]      = useState("");
  const [mode,    setMode]    = useState("merge");
  const [err,     setErr]     = useState("");
  const [busy,    setBusy]    = useState(false);
  const [preview, setPreview] = useState(null);
  const [raw,     setRaw]     = useState(null);
  const [fname,   setFname]   = useState("");
  const fileRef               = useRef();

  function pickFile(e) {
    const f = e.target.files[0]; if (!f) return;
    setFname(f.name);
    const r = new FileReader(); r.onload = ev => setRaw(ev.target.result); r.readAsText(f);
  }

  async function unlock() {
    setErr("");
    if (!raw) { setErr("Please select a backup file first."); return; }
    if (!pw)  { setErr("Enter the backup password."); return; }
    setBusy(true);
    try { setPreview(await importBackup(raw, pw)); }
    catch { setErr("Wrong backup password or corrupted file."); }
    setBusy(false);
  }

  async function confirm() {
    const merged = mode==="replace"
      ? preview
      : [...current, ...preview.filter(v=>!current.find(c=>c.id===v.id))];
    await onImport(merged);
    toast(`Imported ${preview.length} entries!`);
    onClose();
  }

  return (
    <div className="ov" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="mdl">
        <div className="mhdl"/>
        <div className="mhdr">
          <button className="ibtn" onClick={onClose}><Ic d={I.x} size={17}/></button>
          <div className="mtit">Import Backup</div>
          <div style={{width:36}}/>
        </div>
        <div className="mbdy">
          {!preview ? <>
            <div className="inf" style={{marginBottom:16}}>
              <Ic d={I.info} size={16} color="var(--ac2)" sw={2} style={{flexShrink:0,marginTop:1}}/>
              <div>Select your <b style={{color:"var(--tx)"}}>vault-backup-*.json</b> file and enter the backup password you chose when exporting.</div>
            </div>
            <input type="file" accept=".json,application/json" ref={fileRef} style={{display:"none"}} onChange={pickFile}/>
            <div className="upz" style={{marginBottom:14}} onClick={()=>fileRef.current.click()}>
              <Ic d={I.ul} size={22}/>
              <div style={{marginTop:7,fontWeight:raw?600:400,color:raw?"var(--grn)":undefined}}>
                {raw?`✓ ${fname}`:"Tap to select backup file"}
              </div>
              <div style={{fontSize:11,marginTop:4,opacity:.7}}>vault-backup-*.json</div>
            </div>
            <div className="ig"><label className="lbl">Backup Password</label>
              <PwInp value={pw} onChange={setPw} placeholder="Backup password"/></div>
            {err && <div className="err">{err}</div>}
            <button className="btn btn-p" style={{marginTop:8}} onClick={unlock} disabled={busy}>
              {busy?"Decrypting…":"Unlock Backup"}
            </button>
          </> : <>
            <div className="ok-msg" style={{marginBottom:16}}>✓ Found {preview.length} entries in backup</div>
            <div className="fsec">
              <div className="fsec-t">Import Mode</div>
              <div style={{display:"flex",gap:9}}>
                {[
                  {id:"merge",  label:"Merge",  sub:"Add new entries only",    color:"var(--ac)",  bg:"rgba(124,58,237,.14)"},
                  {id:"replace",label:"Replace", sub:"Overwrite current vault", color:"var(--red)", bg:"rgba(239,68,68,.12)"},
                ].map(m=>(
                  <div key={m.id} onClick={()=>setMode(m.id)} style={{
                    flex:1,padding:13,borderRadius:"var(--rs)",cursor:"pointer",textAlign:"center",
                    background:mode===m.id?m.bg:"var(--s2)",
                    border:`1px solid ${mode===m.id?m.color:"var(--bd)"}`,transition:"all .2s"
                  }}>
                    <div style={{fontSize:13,fontWeight:700,color:mode===m.id?m.color:"var(--tx)"}}>{m.label}</div>
                    <div style={{fontSize:11,color:"var(--mu)",marginTop:4}}>{m.sub}</div>
                  </div>
                ))}
              </div>
              {mode==="replace" && (
                <div className="wrn" style={{marginTop:11}}>
                  <Ic d={I.info} size={15} sw={2} style={{flexShrink:0}}/>
                  <div>This will delete all <b>{current.length}</b> current entries and replace with <b>{preview.length}</b> from backup.</div>
                </div>
              )}
            </div>
            <button className="btn btn-p" onClick={confirm}>Confirm Import ({preview.length} entries)</button>
            <button className="btn btn-g" style={{marginTop:9}} onClick={()=>setPreview(null)}>← Back</button>
          </>}
          <button className="btn btn-g" style={{marginTop:9}} onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

// ─── Settings Screen ──────────────────────────────────────────────────────────
function SettingsScreen({ vault, onImport, toast, onLogout }) {
  const [showExp, setShowExp] = useState(false);
  const [showImp, setShowImp] = useState(false);

  return (
    <div className="spage">
      <div className="spage-title">Settings</div>

      <div className="shead">Storage</div>
      <div className="sitem" style={{cursor:"default"}}>
        <div className="sicobox" style={{background:"rgba(34,197,94,.12)"}}>
          <Ic d={I.db} size={20} color="var(--grn)"/>
        </div>
        <div style={{flex:1}}>
          <div className="slabel">IndexedDB Storage</div>
          <div className="ssub">{vault.length} entries · No storage size limit</div>
          <div className="badge"><Ic d={I.check} size={11} sw={2.5}/>Active</div>
        </div>
      </div>

      <div className="shead">Backup & Restore</div>
      <div className="sitem" onClick={()=>setShowExp(true)}>
        <div className="sicobox" style={{background:"rgba(34,197,94,.12)"}}>
          <Ic d={I.dl} size={20} color="var(--grn)"/>
        </div>
        <div style={{flex:1}}>
          <div className="slabel">Export Backup</div>
          <div className="ssub">Download encrypted .json · {vault.length} entries</div>
        </div>
        <Ic d={I.arr} size={17} color="var(--mu)"/>
      </div>
      <div className="sitem" onClick={()=>setShowImp(true)}>
        <div className="sicobox" style={{background:"rgba(99,102,241,.12)"}}>
          <Ic d={I.ul} size={20} color="#6366f1"/>
        </div>
        <div style={{flex:1}}>
          <div className="slabel">Import Backup</div>
          <div className="ssub">Restore from a backup file</div>
        </div>
        <Ic d={I.arr} size={17} color="var(--mu)"/>
      </div>

      <div className="shead">How Backups Work</div>
      <div className="inf">
        <Ic d={I.info} size={16} color="var(--ac2)" sw={2} style={{flexShrink:0,marginTop:2}}/>
        <div>
          <b style={{color:"var(--tx)"}}>Before uninstalling</b> — export a backup, set a backup password, and save the file to WhatsApp, email, or Google Drive.<br/><br/>
          <b style={{color:"var(--tx)"}}>After reinstalling</b> — create a new master password, go to Import Backup, pick the file, and enter your backup password.<br/><br/>
          The backup file is separately encrypted — different password from your master password.
        </div>
      </div>

      <div className="shead">Security</div>
      <div className="sitem" onClick={onLogout}>
        <div className="sicobox" style={{background:"rgba(239,68,68,.1)"}}>
          <Ic d={I.logout} size={20} color="var(--red)"/>
        </div>
        <div style={{flex:1}}>
          <div className="slabel" style={{color:"var(--red)"}}>Lock Vault</div>
          <div className="ssub">Require master password to re-enter</div>
        </div>
      </div>

      {showExp && <ExportModal vault={vault} onClose={()=>setShowExp(false)} toast={toast}/>}
      {showImp && <ImportModal current={vault} onImport={onImport} onClose={()=>setShowImp(false)} toast={toast}/>}
    </div>
  );
}

// ─── Item Form ────────────────────────────────────────────────────────────────
function ItemForm({ initial, onSave, onClose }) {
  const [form, setForm] = useState(
    initial || {name:"",category:"login",username:"",password:"",url:"",note:"",images:[]}
  );
  const [compressing, setCompressing] = useState(false);
  const fileRef = useRef();
  const set = (k,v) => setForm(f=>({...f,[k]:v}));

  async function pickImages(files) {
    setCompressing(true);
    for (const file of Array.from(files)) {
      const r = new FileReader();
      const dataUrl = await new Promise(res => { r.onload = e => res(e.target.result); r.readAsDataURL(file); });
      const compressed = await compressImage(dataUrl);
      setForm(f => ({...f, images: [...(f.images||[]), compressed]}));
    }
    setCompressing(false);
  }

  function save() {
    if (!form.name.trim()) return;
    onSave({...form, id: initial?.id || crypto.randomUUID(), updatedAt: Date.now()});
  }

  return (
    <div className="ov" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="mdl">
        <div className="mhdl"/>
        <div className="mhdr">
          <button className="ibtn" onClick={onClose}><Ic d={I.x} size={17}/></button>
          <div className="mtit">{initial?"Edit Entry":"New Entry"}</div>
          <button className="btn btn-p" style={{width:"auto",padding:"8px 16px",fontSize:14}} onClick={save}>Save</button>
        </div>
        <div className="mbdy">
          <div className="fsec">
            <div className="fsec-t">Category</div>
            <div style={{display:"flex",gap:7,flexWrap:"wrap"}}>
              {CATS.map(c=>(
                <button key={c.id} className="pill" onClick={()=>set("category",c.id)}
                  style={form.category===c.id?{background:c.color+"22",borderColor:c.color,color:c.color}:{}}>
                  <Ic d={c.icon} size={13} color={form.category===c.id?c.color:"currentColor"}/>{c.label}
                </button>
              ))}
            </div>
          </div>

          <div className="fsec">
            <div className="fsec-t">Details</div>
            <div className="ig"><label className="lbl">Name *</label>
              <input className="inp" value={form.name} onChange={e=>set("name",e.target.value)} placeholder="e.g. Gmail, Chase, Home WiFi"/></div>
            {(form.category==="login"||form.category==="other") && <>
              <div className="ig"><label className="lbl">Username / Email</label>
                <input className="inp" value={form.username} onChange={e=>set("username",e.target.value)} placeholder="user@example.com"/></div>
              <div className="ig"><label className="lbl">Password</label>
                <div className="prow">
                  <PwInp value={form.password} onChange={v=>set("password",v)} placeholder="Password" strength/>
                  <button className="gbtn" onClick={()=>set("password",genPw())}><Ic d={I.spin} size={14}/>Generate</button>
                </div>
              </div>
              <div className="ig"><label className="lbl">Website URL</label>
                <input className="inp" value={form.url} onChange={e=>set("url",e.target.value)} placeholder="https://example.com"/></div>
            </>}
            {form.category==="card" && <>
              <div className="ig"><label className="lbl">Card Number</label>
                <input className="inp" value={form.username} onChange={e=>set("username",e.target.value)} placeholder="•••• •••• •••• ••••"/></div>
              <div className="ig"><label className="lbl">PIN / CVV</label>
                <PwInp value={form.password} onChange={v=>set("password",v)} placeholder="PIN or CVV"/></div>
            </>}
            {form.category==="wifi" && <>
              <div className="ig"><label className="lbl">Network Name (SSID)</label>
                <input className="inp" value={form.username} onChange={e=>set("username",e.target.value)} placeholder="My WiFi Network"/></div>
              <div className="ig"><label className="lbl">Wi-Fi Password</label>
                <PwInp value={form.password} onChange={v=>set("password",v)} placeholder="Wi-Fi password" strength/></div>
            </>}
            <div className="ig"><label className="lbl">Notes</label>
              <textarea className="inp" value={form.note} onChange={e=>set("note",e.target.value)} placeholder="Optional notes…"/></div>
          </div>

          <div className="fsec">
            <div className="fsec-t">Images {compressing && <span style={{color:"var(--ac2)",fontWeight:400,textTransform:"none",letterSpacing:0}}> — compressing…</span>}</div>
            <input type="file" accept="image/*" multiple ref={fileRef} style={{display:"none"}} onChange={e=>pickImages(e.target.files)}/>
            <div className="upz" onClick={()=>fileRef.current.click()}>
              <Ic d={I.image} size={22}/>
              <div style={{marginTop:7}}>Tap to attach images</div>
              <div style={{fontSize:11,marginTop:3,opacity:.6}}>Auto-compressed · No size limit</div>
            </div>
            {form.images?.length>0 && (
              <div className="ipgrid">
                {form.images.map((img,i)=>(
                  <div key={i} className="ipbox">
                    <img src={img} alt=""/>
                    <div className="ipdel" onClick={()=>set("images",form.images.filter((_,j)=>j!==i))}>
                      <Ic d={I.x} size={9} color="#fff" sw={3}/>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Item Detail ──────────────────────────────────────────────────────────────
function ItemDetail({ item, onEdit, onDelete, onClose }) {
  const [showPw, setShowPw] = useState(false);
  const [copied, setCopied] = useState(null);
  const [lb,     setLb]     = useState(null);
  const color = catColor(item.category);

  function copy(text, tag) {
    navigator.clipboard.writeText(text).catch(()=>{});
    setCopied(tag); setTimeout(()=>setCopied(null),2000);
  }

  return <>
    <div className="ov" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="mdl">
        <div className="mhdl"/>
        <div className="mhdr">
          <button className="ibtn" onClick={onClose}><Ic d={I.back} size={17}/></button>
          <div className="mtit">Details</div>
          <button className="ibtn" onClick={onEdit}><Ic d={I.edit} size={17}/></button>
        </div>
        <div className="dhero">
          <div className="dico" style={{background:color+"22"}}>
            {item.images?.[0]?<img src={item.images[0]} alt=""/>:<Ic d={catIcon(item.category)} size={24} color={color}/>}
          </div>
          <div>
            <div className="dtit">{item.name}</div>
            <div className="dcat" style={{color}}>{catLabel(item.category)}</div>
          </div>
        </div>
        {item.username && <div className="frow">
          <div className="flbl">{item.category==="card"?"Number":item.category==="wifi"?"SSID":"Username"}</div>
          <div className="fval">{item.username}</div>
          <div className="ficb" onClick={()=>copy(item.username,"u")}><Ic d={copied==="u"?I.check:I.copy} size={14} color={copied==="u"?"var(--grn)":undefined}/></div>
        </div>}
        {item.password && <div className="frow">
          <div className="flbl">{item.category==="card"?"PIN/CVV":"Password"}</div>
          <div className="fval">{showPw?item.password:"•".repeat(Math.min(item.password.length,14))}</div>
          <div style={{display:"flex",gap:5}}>
            <div className="ficb" onClick={()=>setShowPw(v=>!v)}><Ic d={showPw?I.eyeOff:I.eye} size={14}/></div>
            <div className="ficb" onClick={()=>copy(item.password,"p")}><Ic d={copied==="p"?I.check:I.copy} size={14} color={copied==="p"?"var(--grn)":undefined}/></div>
          </div>
        </div>}
        {item.url && <div className="frow">
          <div className="flbl">URL</div>
          <div className="fval" style={{fontSize:13}}>{item.url}</div>
          <div className="ficb" onClick={()=>copy(item.url,"l")}><Ic d={copied==="l"?I.check:I.copy} size={14} color={copied==="l"?"var(--grn)":undefined}/></div>
        </div>}
        {item.note && <div className="frow" style={{flexDirection:"column",alignItems:"flex-start",gap:7}}>
          <div className="flbl">Notes</div>
          <div className="fval" style={{fontFamily:"inherit",letterSpacing:0,lineHeight:1.5}}>{item.note}</div>
        </div>}
        {item.images?.length>0 && <>
          <div style={{padding:"12px 18px 4px",fontSize:11,color:"var(--mu)",fontWeight:700,letterSpacing:1,textTransform:"uppercase"}}>
            Images ({item.images.length})
          </div>
          <div className="igrid">
            {item.images.map((img,i)=><div key={i} className="ithumb" onClick={()=>setLb(img)}><img src={img} alt=""/></div>)}
          </div>
        </>}
        <div className="arow">
          <button className="btn btn-d" onClick={onDelete} style={{flex:1}}>
            <Ic d={I.trash} size={16}/>Delete Entry
          </button>
        </div>
      </div>
    </div>
    {lb && <div className="lb" onClick={()=>setLb(null)}><img src={lb} alt=""/></div>}
  </>;
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [key,      setKey]      = useState(null);
  const [vault,    setVault]    = useState([]);
  const [loading,  setLoading]  = useState(true);  // initial DB check
  const [tab,      setTab]      = useState("vault");
  const [search,   setSearch]   = useState("");
  const [catFilt,  setCatFilt]  = useState("all");
  const [detail,   setDetail]   = useState(null);
  const [editing,  setEditing]  = useState(null);
  const [adding,   setAdding]   = useState(false);
  const [toast,    setToast]    = useState(null);
  const timer = useRef();

  // Just open DB on mount to confirm IndexedDB is available
  useEffect(() => {
    openDB().then(db => { db.close(); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  function showToast(msg, type="ok") {
    clearTimeout(timer.current);
    setToast({msg, type});
    timer.current = setTimeout(()=>setToast(null), 2400);
  }

  async function handleAuth(derivedKey) {
    // Migrate old localStorage vault if present
    await migrateFromLocalStorage(derivedKey);
    const items = await idbLoadAll(derivedKey);
    setKey(derivedKey);
    setVault(items);
  }

  // Save a single item to IndexedDB
  async function persistSave(item) {
    await idbSaveItem(item, key);
    // Refresh vault from DB to keep order correct
    const fresh = await idbLoadAll(key);
    setVault(fresh);
  }

  // Delete a single item from IndexedDB
  async function persistDelete(id) {
    await idbDeleteItem(id);
    setVault(v => v.filter(x => x.id !== id));
  }

  // Replace entire vault (used for import)
  async function persistAll(items) {
    await idbClear();
    for (const item of items) await idbSaveItem(item, key);
    const fresh = await idbLoadAll(key);
    setVault(fresh);
  }

  async function handleSave(item) {
    try {
      await persistSave(item);
      setAdding(false); setEditing(null); setDetail(item);
      showToast(vault.some(v=>v.id===item.id) ? "Entry updated ✓" : "Entry saved ✓");
    } catch(e) {
      showToast("Save failed: " + e.message, "error");
    }
  }

  async function handleDelete(id) {
    try {
      await persistDelete(id);
      setDetail(null); showToast("Entry deleted");
    } catch(e) {
      showToast("Delete failed.", "error");
    }
  }

  async function handleImport(items) {
    try {
      await persistAll(items);
      setTab("vault");
      showToast(`Imported ${items.length} entries!`);
    } catch(e) {
      showToast("Import failed.", "error");
    }
  }

  function handleLogout() {
    setKey(null); setVault([]); setDetail(null); setEditing(null); setAdding(false); setTab("vault");
  }

  // Filtering
  const filtered = vault.filter(v => {
    if (catFilt !== "all" && v.category !== catFilt) return false;
    const q = search.toLowerCase();
    return !q || v.name.toLowerCase().includes(q) || (v.username||"").toLowerCase().includes(q) || (v.url||"").toLowerCase().includes(q);
  });
  const grouped = CATS.reduce((acc,c) => {
    const items = filtered.filter(v => v.category === c.id);
    if (items.length) acc[c.id] = items;
    return acc;
  }, {});

  // Loading screen while DB initialises
  if (loading) return (
    <><style>{CSS}</style>
    <div className="app"><div className="loading">
      <div className="spinner"/>
      <div style={{fontSize:14}}>Initialising vault…</div>
    </div></div></>
  );

  // Auth screen
  if (!key) return (
    <><style>{CSS}</style><div className="app"><AuthScreen onAuth={handleAuth}/></div></>
  );

  // Main app
  return (
    <><style>{CSS}</style>
    <div className="app">

      {tab==="vault" && <>
        <div className="hdr">
          <div className="hdr-row">
            <div className="hdr-logo">
              <div className="hdr-logobox"><Ic d={I.shield} size={17} color="#fff" sw={2}/></div>
              <div className="hdr-title">Vault</div>
            </div>
            <button className="ibtn" onClick={handleLogout} title="Lock">
              <Ic d={I.logout} size={17}/>
            </button>
          </div>
          <div className="sbox">
            <div className="sico"><Ic d={I.search} size={15}/></div>
            <input className="sinp" placeholder="Search vault…" value={search} onChange={e=>setSearch(e.target.value)}/>
          </div>
        </div>

        <div className="pills">
          {[{id:"all",label:"All",icon:I.shield,color:"#7c3aed"},...CATS].map(c=>(
            <button key={c.id} className="pill"
              style={catFilt===c.id?{background:c.color+"22",borderColor:c.color,color:c.color}:{}}
              onClick={()=>setCatFilt(c.id)}>
              <Ic d={c.icon} size={12} color={catFilt===c.id?c.color:"currentColor"}/>{c.label}
            </button>
          ))}
        </div>

        <div className="vlist">
          {filtered.length===0 ? (
            <div className="empty">
              <Ic d={I.lock} size={48}/>
              <div style={{fontWeight:600,fontSize:15}}>{search?"No results found":"Your vault is empty"}</div>
              <div style={{fontSize:13,marginTop:5,opacity:.7}}>{search?"Try a different search":"Tap + to add your first entry"}</div>
            </div>
          ) : Object.entries(grouped).map(([cid,items])=>(
            <div key={cid}>
              <div className="slbl">{catLabel(cid)}</div>
              {items.map(item=>{
                const col = catColor(item.category);
                return (
                  <div key={item.id} className="vitem" onClick={()=>setDetail(item)}>
                    <div style={{position:"absolute",left:0,top:0,bottom:0,width:3,background:col,borderRadius:"99px 0 0 99px"}}/>
                    <div className="vico" style={{background:col+"22"}}>
                      {item.images?.[0]?<img src={item.images[0]} alt=""/>:<Ic d={catIcon(item.category)} size={19} color={col}/>}
                    </div>
                    <div className="vinf">
                      <div className="vname">{item.name}</div>
                      <div className="vsub">{item.username||item.url||catLabel(item.category)}</div>
                    </div>
                    <Ic d={I.arr} size={16} color="var(--mu)"/>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </>}

      {tab==="settings" && (
        <SettingsScreen vault={vault} onImport={handleImport} toast={showToast} onLogout={handleLogout}/>
      )}

      {/* FAB pair — Settings left, Add right — always visible */}
      <div className="fab-wrap">
        <button
          className={"fab fab-set"+(tab==="settings"?" on":"")}
          onClick={()=>setTab(t=>t==="settings"?"vault":"settings")}
          title="Settings">
          <Ic d={I.cog} size={22} color={tab==="settings"?"var(--ac2)":"var(--mu)"}/>
        </button>
        <button className="fab fab-add" onClick={()=>{setTab("vault");setAdding(true);}} title="Add entry">
          <Ic d={I.plus} size={24} sw={2.2}/>
        </button>
      </div>

      {/* Modals */}
      {detail && !editing && (
        <ItemDetail
          item={detail}
          onEdit={()=>{setEditing(detail);setDetail(null);}}
          onDelete={()=>handleDelete(detail.id)}
          onClose={()=>setDetail(null)}
        />
      )}
      {(adding||editing) && (
        <ItemForm
          initial={editing}
          onSave={handleSave}
          onClose={()=>{setAdding(false);setEditing(null);if(editing)setDetail(editing);}}
        />
      )}
      {toast && <Toast msg={toast.msg} type={toast.type}/>}
    </div>
    </>
  );
}
