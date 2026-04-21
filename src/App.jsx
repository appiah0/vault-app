import { useState, useEffect, useRef, useCallback } from "react";

// ─── Crypto helpers (AES-GCM via WebCrypto) ───────────────────────────────────
const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function deriveKey(password, salt) {
  const base = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(text));
  const buf = new Uint8Array(iv.byteLength + ct.byteLength);
  buf.set(iv, 0);
  buf.set(new Uint8Array(ct), iv.byteLength);
  return btoa(String.fromCharCode(...buf));
}

async function decrypt(b64, key) {
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const iv = buf.slice(0, 12);
  const ct = buf.slice(12);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return decoder.decode(pt);
}

// ─── Storage helpers ──────────────────────────────────────────────────────────
const SALT_KEY = "pm_salt";
const VERIFY_KEY = "pm_verify";
const VAULT_KEY = "pm_vault";
const VERIFY_PLAINTEXT = "VAULT_OK";

function getSalt() {
  const s = localStorage.getItem(SALT_KEY);
  if (s) return Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(SALT_KEY, btoa(String.fromCharCode(...salt)));
  return salt;
}

async function saveVerifier(key) {
  const enc = await encrypt(VERIFY_PLAINTEXT, key);
  localStorage.setItem(VERIFY_KEY, enc);
}

async function checkVerifier(key) {
  const enc = localStorage.getItem(VERIFY_KEY);
  if (!enc) return false;
  try {
    const dec = await decrypt(enc, key);
    return dec === VERIFY_PLAINTEXT;
  } catch { return false; }
}

async function loadVault(key) {
  const enc = localStorage.getItem(VAULT_KEY);
  if (!enc) return [];
  try { return JSON.parse(await decrypt(enc, key)); } catch { return []; }
}

async function saveVault(items, key) {
  const enc = await encrypt(JSON.stringify(items), key);
  localStorage.setItem(VAULT_KEY, enc);
}

// ─── Icons ────────────────────────────────────────────────────────────────────
const Icon = ({ d, size = 20, color = "currentColor", strokeWidth = 1.7 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);

const icons = {
  lock: "M19 11H5a2 2 0 00-2 2v7a2 2 0 002 2h14a2 2 0 002-2v-7a2 2 0 00-2-2zM7 11V7a5 5 0 0110 0v4",
  eye: "M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z M12 9a3 3 0 100 6 3 3 0 000-6z",
  eyeOff: "M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24 M1 1l22 22",
  plus: "M12 5v14M5 12h14",
  search: "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z",
  edit: "M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7 M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z",
  trash: "M3 6h18M8 6V4h8v2M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6",
  copy: "M8 4H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-2 M8 4a2 2 0 012-2h4a2 2 0 012 2v0a2 2 0 01-2 2h-4a2 2 0 01-2-2z",
  check: "M20 6L9 17l-5-5",
  x: "M18 6L6 18M6 6l12 12",
  image: "M21 15a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h4l2-3h4l2 3h4a2 2 0 012 2z M12 13a3 3 0 100-6 3 3 0 000 6z",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  key: "M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4",
  globe: "M12 2a10 10 0 100 20A10 10 0 0012 2z M2 12h20 M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z",
  user: "M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2 M12 11a4 4 0 100-8 4 4 0 000 8z",
  note: "M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z M14 2v6h6 M16 13H8m8 4H8m2-8H8",
  creditCard: "M1 4h22v16H1z M1 10h22",
  wifi: "M5 12.55a11 11 0 0114.08 0 M1.42 9a16 16 0 0121.16 0 M8.53 16.11a6 6 0 016.95 0 M12 20h.01",
  back: "M19 12H5m7-7l-7 7 7 7",
  logout: "M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4 M16 17l5-5-5-5 M21 12H9",
  generate: "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15",
};

// ─── Category config ──────────────────────────────────────────────────────────
const CATEGORIES = [
  { id: "login", label: "Login", icon: icons.key, color: "#6366f1" },
  { id: "card", label: "Card", icon: icons.creditCard, color: "#ec4899" },
  { id: "wifi", label: "Wi-Fi", icon: icons.wifi, color: "#14b8a6" },
  { id: "note", label: "Note", icon: icons.note, color: "#f59e0b" },
  { id: "other", label: "Other", icon: icons.globe, color: "#8b5cf6" },
];

function categoryColor(id) {
  return CATEGORIES.find(c => c.id === id)?.color || "#6366f1";
}
function categoryIcon(id) {
  return CATEGORIES.find(c => c.id === id)?.icon || icons.key;
}

// ─── Password strength ────────────────────────────────────────────────────────
function strength(pw) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 14) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return s; // 0-5
}

function genPassword(len = 16) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
  return Array.from(crypto.getRandomValues(new Uint8Array(len))).map(b => chars[b % chars.length]).join("");
}

// ─── Styles ───────────────────────────────────────────────────────────────────
const css = `
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #0a0a0f;
    --surface: #12121a;
    --surface2: #1a1a26;
    --surface3: #22223a;
    --border: rgba(255,255,255,0.07);
    --text: #f0f0ff;
    --muted: #7070a0;
    --accent: #7c3aed;
    --accent2: #a78bfa;
    --danger: #ef4444;
    --success: #22c55e;
    --radius: 16px;
    --radius-sm: 10px;
    --shadow: 0 4px 24px rgba(0,0,0,0.5);
  }

  body { background: var(--bg); color: var(--text); font-family: 'Space Grotesk', sans-serif; }

  .app {
    max-width: 420px;
    min-height: 100vh;
    margin: 0 auto;
    background: var(--bg);
    position: relative;
    overflow: hidden;
  }

  /* ─── Auth Screen ─── */
  .auth-bg {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 32px 24px;
    background: radial-gradient(ellipse at 50% 0%, rgba(124,58,237,0.25) 0%, transparent 65%),
                radial-gradient(ellipse at 80% 100%, rgba(99,102,241,0.15) 0%, transparent 60%),
                var(--bg);
  }

  .auth-logo {
    width: 72px; height: 72px;
    background: linear-gradient(135deg, var(--accent), #6366f1);
    border-radius: 24px;
    display: flex; align-items: center; justify-content: center;
    margin-bottom: 20px;
    box-shadow: 0 0 40px rgba(124,58,237,0.4);
  }

  .auth-title { font-size: 28px; font-weight: 700; text-align: center; letter-spacing: -0.5px; }
  .auth-sub { color: var(--muted); font-size: 14px; text-align: center; margin-top: 6px; }

  .auth-card {
    width: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 28px;
    margin-top: 32px;
  }

  .input-group { margin-bottom: 16px; }
  .input-label { font-size: 12px; color: var(--muted); font-weight: 500; letter-spacing: 0.5px; text-transform: uppercase; margin-bottom: 8px; display: block; }

  .input-wrap {
    position: relative;
    display: flex;
    align-items: center;
  }

  .input {
    width: 100%;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text);
    font-family: 'Space Grotesk', sans-serif;
    font-size: 15px;
    padding: 13px 44px 13px 16px;
    outline: none;
    transition: border-color 0.2s;
  }
  .input:focus { border-color: var(--accent); }
  .input::placeholder { color: var(--muted); }

  .eye-btn {
    position: absolute; right: 12px;
    background: none; border: none; cursor: pointer;
    color: var(--muted); padding: 0; display: flex; align-items: center;
    transition: color 0.2s;
  }
  .eye-btn:hover { color: var(--text); }

  .strength-bar { display: flex; gap: 4px; margin-top: 8px; }
  .strength-seg { flex: 1; height: 3px; border-radius: 99px; background: var(--surface3); transition: background 0.3s; }

  .btn {
    width: 100%; padding: 14px;
    border: none; border-radius: var(--radius-sm);
    font-family: 'Space Grotesk', sans-serif;
    font-size: 15px; font-weight: 600;
    cursor: pointer; transition: all 0.2s;
  }
  .btn-primary {
    background: linear-gradient(135deg, var(--accent), #6366f1);
    color: #fff;
    box-shadow: 0 4px 20px rgba(124,58,237,0.35);
  }
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 24px rgba(124,58,237,0.5); }
  .btn-primary:active { transform: translateY(0); }
  .btn-ghost { background: var(--surface2); color: var(--text); border: 1px solid var(--border); }
  .btn-ghost:hover { border-color: var(--accent2); color: var(--accent2); }
  .btn-danger { background: rgba(239,68,68,0.15); color: var(--danger); border: 1px solid rgba(239,68,68,0.25); }

  .error-msg {
    background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.25);
    color: var(--danger); border-radius: var(--radius-sm);
    padding: 10px 14px; font-size: 13px; margin-top: 12px;
    text-align: center;
  }

  /* ─── Header ─── */
  .header {
    padding: 56px 20px 16px;
    background: linear-gradient(to bottom, var(--surface), transparent);
    position: sticky; top: 0; z-index: 10;
    backdrop-filter: blur(16px);
  }

  .header-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
  .header-logo { display: flex; align-items: center; gap: 10px; }
  .header-logo-icon {
    width: 36px; height: 36px;
    background: linear-gradient(135deg, var(--accent), #6366f1);
    border-radius: 10px; display: flex; align-items: center; justify-content: center;
  }
  .header-title { font-size: 20px; font-weight: 700; letter-spacing: -0.3px; }
  .icon-btn {
    width: 38px; height: 38px;
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 10px; display: flex; align-items: center; justify-content: center;
    cursor: pointer; color: var(--muted); transition: all 0.2s;
  }
  .icon-btn:hover { border-color: var(--accent2); color: var(--accent2); }

  .search-wrap { position: relative; }
  .search-icon { position: absolute; left: 13px; top: 50%; transform: translateY(-50%); color: var(--muted); pointer-events: none; }
  .search-input {
    width: 100%; background: var(--surface2);
    border: 1px solid var(--border); border-radius: var(--radius-sm);
    color: var(--text); font-family: 'Space Grotesk', sans-serif; font-size: 14px;
    padding: 11px 16px 11px 40px; outline: none; transition: border-color 0.2s;
  }
  .search-input:focus { border-color: var(--accent); }
  .search-input::placeholder { color: var(--muted); }

  /* ─── Category Pills ─── */
  .cat-strip { display: flex; gap: 8px; padding: 12px 20px; overflow-x: auto; }
  .cat-strip::-webkit-scrollbar { display: none; }
  .cat-pill {
    flex-shrink: 0; display: flex; align-items: center; gap: 6px;
    padding: 7px 14px; border-radius: 99px;
    background: var(--surface2); border: 1px solid var(--border);
    font-size: 13px; font-weight: 500; cursor: pointer;
    transition: all 0.2s; color: var(--muted); white-space: nowrap;
  }
  .cat-pill.active { color: #fff; border-color: transparent; }

  /* ─── Vault List ─── */
  .vault-list { padding: 0 20px 100px; }

  .section-label { font-size: 11px; color: var(--muted); font-weight: 600; letter-spacing: 1px; text-transform: uppercase; margin: 16px 0 10px; }

  .vault-item {
    display: flex; align-items: center; gap: 14px;
    padding: 14px 16px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 10px;
    cursor: pointer;
    transition: all 0.2s;
    position: relative;
    overflow: hidden;
  }
  .vault-item::before {
    content: ''; position: absolute; left: 0; top: 0; bottom: 0;
    width: 3px;
    border-radius: 99px 0 0 99px;
  }
  .vault-item:hover { border-color: rgba(255,255,255,0.12); transform: translateX(2px); }

  .vault-icon {
    width: 44px; height: 44px; flex-shrink: 0;
    border-radius: 12px; display: flex; align-items: center; justify-content: center;
    position: relative;
    overflow: hidden;
  }
  .vault-icon img { width: 100%; height: 100%; object-fit: cover; border-radius: 12px; }

  .vault-info { flex: 1; min-width: 0; }
  .vault-name { font-size: 15px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .vault-user { font-size: 12px; color: var(--muted); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  .vault-arrow { color: var(--muted); flex-shrink: 0; }

  /* ─── FAB ─── */
  .fab {
    position: fixed; bottom: 28px; right: calc(50% - 210px + 20px);
    width: 58px; height: 58px;
    background: linear-gradient(135deg, var(--accent), #6366f1);
    border: none; border-radius: 18px;
    box-shadow: 0 6px 28px rgba(124,58,237,0.55);
    display: flex; align-items: center; justify-content: center;
    cursor: pointer; color: #fff;
    transition: all 0.2s;
    z-index: 20;
  }
  .fab:hover { transform: translateY(-2px) scale(1.04); }
  .fab:active { transform: scale(0.97); }

  /* ─── Bottom Nav ─── */
  .bottom-nav {
    position: fixed; bottom: 0; left: 50%; transform: translateX(-50%);
    width: 100%; max-width: 420px;
    background: var(--surface);
    border-top: 1px solid var(--border);
    padding: 10px 0 20px;
    display: flex; justify-content: space-around;
    z-index: 15;
    backdrop-filter: blur(20px);
  }
  .nav-item {
    display: flex; flex-direction: column; align-items: center; gap: 4px;
    font-size: 11px; font-weight: 500;
    color: var(--muted); cursor: pointer; transition: color 0.2s;
    padding: 4px 16px;
  }
  .nav-item.active { color: var(--accent2); }

  /* ─── Detail / Edit Modal ─── */
  .modal-overlay {
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.7);
    backdrop-filter: blur(4px);
    z-index: 50;
    display: flex; align-items: flex-end;
    animation: fadeIn 0.2s ease;
  }
  @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

  .modal {
    width: 100%; max-width: 420px; margin: 0 auto;
    background: var(--surface);
    border-radius: var(--radius) var(--radius) 0 0;
    border: 1px solid var(--border);
    border-bottom: none;
    max-height: 92vh;
    overflow-y: auto;
    animation: slideUp 0.3s cubic-bezier(0.34,1.56,0.64,1);
  }
  @keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }

  .modal-handle {
    width: 36px; height: 4px;
    background: var(--surface3); border-radius: 99px;
    margin: 12px auto 0;
  }

  .modal-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 20px 12px;
    border-bottom: 1px solid var(--border);
  }
  .modal-title { font-size: 17px; font-weight: 700; }

  .modal-body { padding: 20px; }

  /* ─── Detail view ─── */
  .detail-hero {
    display: flex; align-items: center; gap: 16px;
    padding: 16px 20px 20px;
    border-bottom: 1px solid var(--border);
  }
  .detail-icon {
    width: 56px; height: 56px;
    border-radius: 16px; display: flex; align-items: center; justify-content: center;
    overflow: hidden; flex-shrink: 0;
  }
  .detail-icon img { width: 100%; height: 100%; object-fit: cover; }
  .detail-title { font-size: 20px; font-weight: 700; }
  .detail-cat { font-size: 12px; color: var(--muted); margin-top: 3px; }

  .field-row {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 12px;
  }
  .field-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; min-width: 72px; }
  .field-value {
    flex: 1; font-size: 14px;
    font-family: 'JetBrains Mono', monospace;
    word-break: break-all; color: var(--text);
  }
  .field-value.password { letter-spacing: 2px; }
  .field-actions { display: flex; gap: 6px; flex-shrink: 0; }
  .field-icon-btn {
    width: 32px; height: 32px;
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 8px; display: flex; align-items: center; justify-content: center;
    cursor: pointer; color: var(--muted); transition: all 0.15s;
  }
  .field-icon-btn:hover { color: var(--accent2); border-color: var(--accent2); }

  .detail-image-grid {
    padding: 16px 20px;
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;
  }
  .detail-thumb {
    aspect-ratio: 1; border-radius: 10px; overflow: hidden;
    background: var(--surface2);
    cursor: pointer;
  }
  .detail-thumb img { width: 100%; height: 100%; object-fit: cover; }

  .action-row { padding: 16px 20px; display: flex; gap: 10px; }

  /* ─── Form ─── */
  .form-section { margin-bottom: 20px; }
  .form-section-title { font-size: 12px; color: var(--muted); font-weight: 600; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 10px; }

  .image-upload-zone {
    border: 2px dashed var(--border); border-radius: var(--radius-sm);
    padding: 20px; text-align: center; cursor: pointer;
    transition: all 0.2s; color: var(--muted); font-size: 13px;
  }
  .image-upload-zone:hover { border-color: var(--accent); color: var(--accent2); }

  .image-preview-grid { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
  .image-preview {
    width: 72px; height: 72px; border-radius: 10px; overflow: hidden;
    position: relative; background: var(--surface2);
  }
  .image-preview img { width: 100%; height: 100%; object-fit: cover; }
  .image-remove {
    position: absolute; top: 3px; right: 3px;
    width: 18px; height: 18px;
    background: rgba(239,68,68,0.9); border-radius: 99px;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer;
  }

  .gen-btn {
    display: flex; align-items: center; gap: 6px;
    background: var(--surface3); border: 1px solid var(--border);
    color: var(--accent2); border-radius: 8px;
    padding: 8px 12px; font-size: 13px; font-weight: 500;
    cursor: pointer; transition: all 0.2s; margin-top: 8px;
    font-family: 'Space Grotesk', sans-serif;
    white-space: nowrap;
  }
  .gen-btn:hover { border-color: var(--accent2); }

  .pw-row { display: flex; align-items: flex-start; gap: 8px; }
  .pw-row .input-wrap { flex: 1; }

  /* ─── Empty state ─── */
  .empty {
    display: flex; flex-direction: column; align-items: center;
    padding: 60px 20px; text-align: center; color: var(--muted);
  }
  .empty-icon { margin-bottom: 16px; opacity: 0.4; }
  .empty-text { font-size: 15px; font-weight: 500; }
  .empty-sub { font-size: 13px; margin-top: 6px; opacity: 0.7; }

  /* ─── Toast ─── */
  .toast {
    position: fixed; bottom: 100px; left: 50%; transform: translateX(-50%);
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 99px; padding: 10px 20px;
    font-size: 13px; font-weight: 500;
    display: flex; align-items: center; gap: 8px;
    color: var(--success); z-index: 100;
    animation: toastIn 0.2s ease, toastOut 0.3s ease 1.7s forwards;
    white-space: nowrap;
    box-shadow: var(--shadow);
  }
  @keyframes toastIn { from { opacity: 0; transform: translateX(-50%) translateY(12px); } to { opacity: 1; transform: translateX(-50%) translateY(0); } }
  @keyframes toastOut { from { opacity: 1; } to { opacity: 0; } }

  /* ─── Image lightbox ─── */
  .lightbox {
    position: fixed; inset: 0; z-index: 200;
    background: rgba(0,0,0,0.95);
    display: flex; align-items: center; justify-content: center;
    animation: fadeIn 0.15s ease;
    cursor: pointer;
  }
  .lightbox img { max-width: 100%; max-height: 90vh; border-radius: 8px; }

  /* ─── Scrollbar ─── */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--surface3); border-radius: 99px; }

  select.input { appearance: none; }

  textarea.input { resize: none; min-height: 80px; line-height: 1.5; }
`;

// ─── Subcomponents ────────────────────────────────────────────────────────────

function StrengthBar({ pw }) {
  const s = strength(pw);
  const colors = ["#ef4444","#f97316","#eab308","#84cc16","#22c55e"];
  return (
    <div className="strength-bar">
      {[0,1,2,3,4].map(i => (
        <div key={i} className="strength-seg" style={{ background: i < s ? colors[Math.min(s-1,4)] : undefined }} />
      ))}
    </div>
  );
}

function PwInput({ value, onChange, placeholder = "Password", showStrength }) {
  const [show, setShow] = useState(false);
  return (
    <>
      <div className="input-wrap">
        <input className="input" type={show ? "text" : "password"} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} />
        <button className="eye-btn" type="button" onClick={() => setShow(v => !v)}>
          <Icon d={show ? icons.eyeOff : icons.eye} size={17} />
        </button>
      </div>
      {showStrength && value && <StrengthBar pw={value} />}
    </>
  );
}

function Toast({ msg }) {
  return (
    <div className="toast">
      <Icon d={icons.check} size={15} color="var(--success)" />
      {msg}
    </div>
  );
}

// ─── Auth Screen ──────────────────────────────────────────────────────────────
function AuthScreen({ onAuth }) {
  const isNew = !localStorage.getItem(VERIFY_KEY);
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handle() {
    setError(""); setLoading(true);
    try {
      const salt = getSalt();
      const key = await deriveKey(pw, salt);
      if (isNew) {
        if (pw.length < 6) { setError("Password must be at least 6 characters."); setLoading(false); return; }
        if (pw !== confirm) { setError("Passwords don't match."); setLoading(false); return; }
        await saveVerifier(key);
        onAuth(key);
      } else {
        const ok = await checkVerifier(key);
        if (!ok) { setError("Wrong master password. Try again."); setLoading(false); return; }
        onAuth(key);
      }
    } catch (e) { setError("Something went wrong."); }
    setLoading(false);
  }

  return (
    <div className="auth-bg">
      <div className="auth-logo">
        <Icon d={icons.shield} size={32} color="#fff" strokeWidth={2} />
      </div>
      <div className="auth-title">Vault</div>
      <div className="auth-sub">{isNew ? "Create your master password to get started" : "Enter your master password to unlock"}</div>
      <div className="auth-card">
        <div className="input-group">
          <label className="input-label">Master Password</label>
          <PwInput value={pw} onChange={setPw} placeholder="Enter master password" showStrength={isNew} />
        </div>
        {isNew && (
          <div className="input-group">
            <label className="input-label">Confirm Password</label>
            <PwInput value={confirm} onChange={setConfirm} placeholder="Confirm master password" />
          </div>
        )}
        {error && <div className="error-msg">{error}</div>}
        <button className="btn btn-primary" style={{ marginTop: 20 }} onClick={handle} disabled={loading}>
          {loading ? "Unlocking…" : isNew ? "Create Vault" : "Unlock Vault"}
        </button>
      </div>
    </div>
  );
}

// ─── Item Form Modal ──────────────────────────────────────────────────────────
function ItemForm({ initial, onSave, onClose }) {
  const isEdit = !!initial;
  const [form, setForm] = useState(initial || { name: "", category: "login", username: "", password: "", url: "", note: "", images: [] });
  const fileRef = useRef();

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  function handleImages(files) {
    Array.from(files).forEach(file => {
      const reader = new FileReader();
      reader.onload = e => set("images", [...(form.images || []), e.target.result]);
      reader.readAsDataURL(file);
    });
  }

  function removeImage(i) {
    set("images", form.images.filter((_, idx) => idx !== i));
  }

  function save() {
    if (!form.name.trim()) return;
    onSave({ ...form, id: initial?.id || crypto.randomUUID(), updatedAt: Date.now() });
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-handle" />
        <div className="modal-header">
          <button className="icon-btn" onClick={onClose}><Icon d={icons.x} size={17} /></button>
          <div className="modal-title">{isEdit ? "Edit Entry" : "New Entry"}</div>
          <button className="btn btn-primary" style={{ width: "auto", padding: "8px 18px", fontSize: 14 }} onClick={save}>Save</button>
        </div>
        <div className="modal-body">

          {/* Category */}
          <div className="form-section">
            <div className="form-section-title">Category</div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {CATEGORIES.map(c => (
                <button key={c.id} onClick={() => set("category", c.id)} className="cat-pill"
                  style={form.category === c.id ? { background: c.color + "22", borderColor: c.color, color: c.color } : {}}>
                  <Icon d={c.icon} size={13} color={form.category === c.id ? c.color : "currentColor"} />
                  {c.label}
                </button>
              ))}
            </div>
          </div>

          {/* Core fields */}
          <div className="form-section">
            <div className="form-section-title">Details</div>
            <div className="input-group">
              <label className="input-label">Name *</label>
              <input className="input" value={form.name} onChange={e => set("name", e.target.value)} placeholder="e.g. Gmail, Chase, Home WiFi" />
            </div>
            {(form.category === "login" || form.category === "other") && (
              <>
                <div className="input-group">
                  <label className="input-label">Username / Email</label>
                  <input className="input" value={form.username} onChange={e => set("username", e.target.value)} placeholder="user@example.com" />
                </div>
                <div className="input-group">
                  <label className="input-label">Password</label>
                  <div className="pw-row">
                    <PwInput value={form.password} onChange={v => set("password", v)} placeholder="Password" showStrength />
                    <button className="gen-btn" onClick={() => set("password", genPassword())}>
                      <Icon d={icons.generate} size={14} />Generate
                    </button>
                  </div>
                </div>
                <div className="input-group">
                  <label className="input-label">Website URL</label>
                  <input className="input" value={form.url} onChange={e => set("url", e.target.value)} placeholder="https://example.com" />
                </div>
              </>
            )}
            {form.category === "card" && (
              <>
                <div className="input-group">
                  <label className="input-label">Card Number</label>
                  <input className="input" value={form.username} onChange={e => set("username", e.target.value)} placeholder="•••• •••• •••• ••••" />
                </div>
                <div className="input-group">
                  <label className="input-label">PIN / CVV</label>
                  <PwInput value={form.password} onChange={v => set("password", v)} placeholder="PIN or CVV" />
                </div>
              </>
            )}
            {form.category === "wifi" && (
              <>
                <div className="input-group">
                  <label className="input-label">Network Name (SSID)</label>
                  <input className="input" value={form.username} onChange={e => set("username", e.target.value)} placeholder="My WiFi Network" />
                </div>
                <div className="input-group">
                  <label className="input-label">Password</label>
                  <PwInput value={form.password} onChange={v => set("password", v)} placeholder="WiFi password" showStrength />
                </div>
              </>
            )}
            <div className="input-group">
              <label className="input-label">Notes</label>
              <textarea className="input" value={form.note} onChange={e => set("note", e.target.value)} placeholder="Optional notes…" />
            </div>
          </div>

          {/* Images */}
          <div className="form-section">
            <div className="form-section-title">Images</div>
            <input type="file" accept="image/*" multiple ref={fileRef} style={{ display: "none" }} onChange={e => handleImages(e.target.files)} />
            <div className="image-upload-zone" onClick={() => fileRef.current.click()}>
              <Icon d={icons.image} size={22} />
              <div style={{ marginTop: 8 }}>Tap to upload images</div>
              <div style={{ fontSize: 11, marginTop: 4, opacity: 0.7 }}>Attach screenshots, cards, or documents</div>
            </div>
            {form.images?.length > 0 && (
              <div className="image-preview-grid">
                {form.images.map((img, i) => (
                  <div key={i} className="image-preview">
                    <img src={img} alt="" />
                    <div className="image-remove" onClick={() => removeImage(i)}>
                      <Icon d={icons.x} size={10} color="#fff" strokeWidth={2.5} />
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

// ─── Item Detail Modal ────────────────────────────────────────────────────────
function ItemDetail({ item, onEdit, onDelete, onClose }) {
  const [showPw, setShowPw] = useState(false);
  const [copied, setCopied] = useState(null);
  const [lightbox, setLightbox] = useState(null);
  const color = categoryColor(item.category);

  function copy(text, label) {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  }

  const hasPassword = item.password;
  const hasUser = item.username;
  const hasUrl = item.url;
  const hasNote = item.note;

  return (
    <>
      <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
        <div className="modal">
          <div className="modal-handle" />
          <div className="modal-header">
            <button className="icon-btn" onClick={onClose}><Icon d={icons.back} size={17} /></button>
            <div className="modal-title">Details</div>
            <button className="icon-btn" onClick={onEdit}><Icon d={icons.edit} size={17} /></button>
          </div>

          <div className="detail-hero">
            <div className="detail-icon" style={{ background: color + "22" }}>
              {item.images?.[0]
                ? <img src={item.images[0]} alt="" />
                : <Icon d={categoryIcon(item.category)} size={24} color={color} />}
            </div>
            <div>
              <div className="detail-title">{item.name}</div>
              <div className="detail-cat" style={{ color }}>{CATEGORIES.find(c => c.id === item.category)?.label}</div>
            </div>
          </div>

          {hasUser && (
            <div className="field-row">
              <div className="field-label">{item.category === "card" ? "Number" : item.category === "wifi" ? "SSID" : "Username"}</div>
              <div className="field-value">{item.username}</div>
              <div className="field-actions">
                <div className="field-icon-btn" onClick={() => copy(item.username, "user")}>
                  <Icon d={copied === "user" ? icons.check : icons.copy} size={14} color={copied === "user" ? "var(--success)" : undefined} />
                </div>
              </div>
            </div>
          )}

          {hasPassword && (
            <div className="field-row">
              <div className="field-label">{item.category === "card" ? "PIN/CVV" : "Password"}</div>
              <div className={"field-value" + (showPw ? "" : " password")} style={{ fontFamily: showPw ? undefined : "'JetBrains Mono'" }}>
                {showPw ? item.password : "•".repeat(Math.min(item.password.length, 12))}
              </div>
              <div className="field-actions">
                <div className="field-icon-btn" onClick={() => setShowPw(v => !v)}>
                  <Icon d={showPw ? icons.eyeOff : icons.eye} size={14} />
                </div>
                <div className="field-icon-btn" onClick={() => copy(item.password, "pw")}>
                  <Icon d={copied === "pw" ? icons.check : icons.copy} size={14} color={copied === "pw" ? "var(--success)" : undefined} />
                </div>
              </div>
            </div>
          )}

          {hasUrl && (
            <div className="field-row">
              <div className="field-label">URL</div>
              <div className="field-value" style={{ fontSize: 13 }}>{item.url}</div>
              <div className="field-actions">
                <div className="field-icon-btn" onClick={() => copy(item.url, "url")}>
                  <Icon d={copied === "url" ? icons.check : icons.copy} size={14} color={copied === "url" ? "var(--success)" : undefined} />
                </div>
              </div>
            </div>
          )}

          {hasNote && (
            <div className="field-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: 8 }}>
              <div className="field-label">Notes</div>
              <div className="field-value" style={{ fontFamily: "inherit", fontSize: 14, lineHeight: 1.5, letterSpacing: 0 }}>{item.note}</div>
            </div>
          )}

          {item.images?.length > 0 && (
            <>
              <div style={{ padding: "12px 20px 4px", fontSize: 11, color: "var(--muted)", fontWeight: 600, letterSpacing: 1, textTransform: "uppercase" }}>Images</div>
              <div className="detail-image-grid">
                {item.images.map((img, i) => (
                  <div key={i} className="detail-thumb" onClick={() => setLightbox(img)}>
                    <img src={img} alt="" />
                  </div>
                ))}
              </div>
            </>
          )}

          <div className="action-row">
            <button className="btn btn-danger" onClick={onDelete} style={{ flex: 1 }}>
              <Icon d={icons.trash} size={15} style={{ marginRight: 6, display: "inline" }} /> Delete
            </button>
          </div>

        </div>
      </div>

      {lightbox && (
        <div className="lightbox" onClick={() => setLightbox(null)}>
          <img src={lightbox} alt="" />
        </div>
      )}
    </>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [cryptoKey, setCryptoKey] = useState(null);
  const [vault, setVault] = useState([]);
  const [search, setSearch] = useState("");
  const [filterCat, setFilterCat] = useState("all");
  const [detail, setDetail] = useState(null);
  const [editing, setEditing] = useState(null);
  const [adding, setAdding] = useState(false);
  const [toast, setToast] = useState(null);
  const toastTimer = useRef();

  function showToast(msg) {
    clearTimeout(toastTimer.current);
    setToast(msg);
    toastTimer.current = setTimeout(() => setToast(null), 2200);
  }

  async function afterAuth(key) {
    const v = await loadVault(key);
    setCryptoKey(key);
    setVault(v);
  }

  async function persistVault(items) {
    setVault(items);
    await saveVault(items, cryptoKey);
  }

  async function handleSave(item) {
    let updated;
    if (vault.find(v => v.id === item.id)) {
      updated = vault.map(v => v.id === item.id ? item : v);
    } else {
      updated = [item, ...vault];
    }
    await persistVault(updated);
    setAdding(false);
    setEditing(null);
    setDetail(item);
    showToast(vault.find(v => v.id === item.id) ? "Entry updated" : "Entry saved");
  }

  async function handleDelete(id) {
    const updated = vault.filter(v => v.id !== id);
    await persistVault(updated);
    setDetail(null);
    showToast("Entry deleted");
  }

  async function handleLogout() {
    setCryptoKey(null);
    setVault([]);
    setDetail(null);
    setEditing(null);
    setAdding(false);
  }

  const filtered = vault.filter(v => {
    const matchCat = filterCat === "all" || v.category === filterCat;
    const q = search.toLowerCase();
    const matchSearch = !q || v.name.toLowerCase().includes(q) || (v.username || "").toLowerCase().includes(q) || (v.url || "").toLowerCase().includes(q);
    return matchCat && matchSearch;
  });

  const grouped = CATEGORIES.reduce((acc, c) => {
    const items = filtered.filter(v => v.category === c.id);
    if (items.length) acc[c.id] = items;
    return acc;
  }, {});

  if (!cryptoKey) return (
    <>
      <style>{css}</style>
      <div className="app"><AuthScreen onAuth={afterAuth} /></div>
    </>
  );

  return (
    <>
      <style>{css}</style>
      <div className="app">

        {/* Header */}
        <div className="header">
          <div className="header-row">
            <div className="header-logo">
              <div className="header-logo-icon">
                <Icon d={icons.shield} size={18} color="#fff" strokeWidth={2} />
              </div>
              <div className="header-title">Vault</div>
            </div>
            <button className="icon-btn" onClick={handleLogout} title="Lock vault">
              <Icon d={icons.logout} size={17} />
            </button>
          </div>
          <div className="search-wrap">
            <div className="search-icon"><Icon d={icons.search} size={16} /></div>
            <input className="search-input" placeholder="Search vault…" value={search} onChange={e => setSearch(e.target.value)} />
          </div>
        </div>

        {/* Category filter */}
        <div className="cat-strip">
          {[{ id: "all", label: "All", icon: icons.shield, color: "#7c3aed" }, ...CATEGORIES].map(c => (
            <button key={c.id} className={"cat-pill" + (filterCat === c.id ? " active" : "")}
              style={filterCat === c.id ? { background: c.color + "22", borderColor: c.color, color: c.color } : {}}
              onClick={() => setFilterCat(c.id)}>
              <Icon d={c.icon} size={13} color={filterCat === c.id ? c.color : "currentColor"} />
              {c.label}
            </button>
          ))}
        </div>

        {/* Vault list */}
        <div className="vault-list">
          {filtered.length === 0 ? (
            <div className="empty">
              <div className="empty-icon"><Icon d={icons.lock} size={48} /></div>
              <div className="empty-text">{search ? "No results found" : "Your vault is empty"}</div>
              <div className="empty-sub">{search ? "Try a different search" : "Tap + to add your first entry"}</div>
            </div>
          ) : (
            Object.entries(grouped).map(([catId, items]) => (
              <div key={catId}>
                <div className="section-label">{CATEGORIES.find(c => c.id === catId)?.label}</div>
                {items.map(item => {
                  const color = categoryColor(item.category);
                  return (
                    <div key={item.id} className="vault-item" onClick={() => setDetail(item)}
                      style={{ "--item-color": color }}>
                      <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 3, background: color, borderRadius: "99px 0 0 99px" }} />
                      <div className="vault-icon" style={{ background: color + "22" }}>
                        {item.images?.[0]
                          ? <img src={item.images[0]} alt="" />
                          : <Icon d={categoryIcon(item.category)} size={20} color={color} />}
                      </div>
                      <div className="vault-info">
                        <div className="vault-name">{item.name}</div>
                        <div className="vault-user">{item.username || item.url || CATEGORIES.find(c => c.id === item.category)?.label}</div>
                      </div>
                      <div className="vault-arrow"><Icon d={icons.back} size={16} style={{ transform: "rotate(180deg)" }} /></div>
                    </div>
                  );
                })}
              </div>
            ))
          )}
        </div>

        {/* FAB */}
        <button className="fab" onClick={() => setAdding(true)}>
          <Icon d={icons.plus} size={26} strokeWidth={2} />
        </button>

        {/* Modals */}
        {detail && !editing && (
          <ItemDetail
            item={detail}
            onEdit={() => { setEditing(detail); setDetail(null); }}
            onDelete={() => handleDelete(detail.id)}
            onClose={() => setDetail(null)}
          />
        )}

        {(adding || editing) && (
          <ItemForm
            initial={editing}
            onSave={handleSave}
            onClose={() => { setAdding(false); setEditing(null); if (editing) setDetail(editing); }}
          />
        )}

        {toast && <Toast msg={toast} />}

      </div>
    </>
  );
}

