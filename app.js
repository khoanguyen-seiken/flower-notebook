/* ---------------------------------------------------------------
   Vellum — a paper-first notebook for iPad, tuned for Apple Pencil
--------------------------------------------------------------- */

/* ===================== Storage (IndexedDB) ===================== */

const DB_NAME = 'vellum-db';
const DB_VERSION = 1;
let dbPromise = null;

function openDB(){
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('notebooks')){
        db.createObjectStore('notebooks', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('meta')){
        db.createObjectStore('meta', { keyPath: 'key' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

async function idbGet(store, key){
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const r = tx.objectStore(store).get(key);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function idbPut(store, value){
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
async function idbDelete(store, key){
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
async function idbAll(store){
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const r = tx.objectStore(store).getAll();
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

const uid = () => Math.random().toString(36).slice(2, 10) + Date.now().toString(36);

function blankPage(){ return { id: uid(), strokes: [] }; }

function newNotebook(name){
  const now = Date.now();
  return {
    id: uid(),
    name: name || 'Untitled Notebook',
    createdAt: now,
    updatedAt: now,
    paperStyle: 'blank',
    currentPageIndex: 0,
    pages: [ blankPage() ]
  };
}

/* ===================== Encryption (PIN -> AES-256-GCM) ===================== */

const textEnc = new TextEncoder();
const textDec = new TextDecoder();

function toB64(buf){
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function fromB64(b64){
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function deriveKey(pin, saltB64){
  const salt = fromB64(saltB64);
  const baseKey = await crypto.subtle.importKey('raw', textEnc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptJSON(key, obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = textEnc.encode(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { iv: toB64(iv.buffer), data: toB64(cipher) };
}
async function decryptJSON(key, blob){
  const iv = new Uint8Array(fromB64(blob.iv));
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, fromB64(blob.data));
  return JSON.parse(textDec.decode(plain));
}

async function decryptNotebookRecord(rec, key){
  key = key || state.cryptoKey;
  if (!rec.enc) return rec;
  const payload = await decryptJSON(key, { iv: rec.iv, data: rec.data });
  return { id: rec.id, updatedAt: rec.updatedAt, ...payload };
}
async function encryptNotebookRecord(nb, key){
  const { id, updatedAt, ...payload } = nb;
  const blob = await encryptJSON(key, payload);
  return { id, updatedAt, enc: true, iv: blob.iv, data: blob.data };
}

async function enableLock(pin){
  const salt = toB64(crypto.getRandomValues(new Uint8Array(16)).buffer);
  const key = await deriveKey(pin, salt);
  const all = await idbAll('notebooks');
  for (const rec of all){
    const plain = rec.enc ? await decryptNotebookRecord(rec, state.cryptoKey) : rec;
    const encRec = await encryptNotebookRecord(plain, key);
    await idbPut('notebooks', encRec);
  }
  const verifier = await encryptJSON(key, { ok: true });
  await idbPut('meta', { key: 'security', value: { enabled: true, salt } });
  await idbPut('meta', { key: 'securityVerifier', value: verifier });
  state.cryptoKey = key;
}

async function disableLock(){
  const all = await idbAll('notebooks');
  for (const rec of all){
    const plain = await decryptNotebookRecord(rec, state.cryptoKey);
    await idbPut('notebooks', plain);
  }
  await idbDelete('meta', 'security');
  await idbDelete('meta', 'securityVerifier');
  state.cryptoKey = null;
}

async function tryUnlock(pin){
  const sec = await idbGet('meta', 'security');
  if (!sec || !sec.value || !sec.value.enabled) return true;
  try {
    const key = await deriveKey(pin, sec.value.salt);
    const verifier = await idbGet('meta', 'securityVerifier');
    const res = await decryptJSON(key, verifier.value);
    if (res && res.ok){ state.cryptoKey = key; return true; }
  } catch (e){ /* wrong pin -> decrypt throws */ }
  return false;
}

function askPin({ title, subtitle, needConfirm = false, okLabel = 'Continue' }){
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'lock-screen pin-modal';
    overlay.innerHTML = `
      <div class="lock-card">
        <h2>${title}</h2>
        <p class="lock-sub">${subtitle}</p>
        <input type="password" inputmode="numeric" pattern="[0-9]*" class="pin-field" placeholder="PIN (4\u201312 digits)" maxlength="12" autocomplete="off">
        ${needConfirm ? '<input type="password" inputmode="numeric" pattern="[0-9]*" class="pin-field pin-confirm" placeholder="Confirm PIN" maxlength="12" autocomplete="off">' : ''}
        <div class="lock-error"></div>
        <div class="pin-actions">
          <button class="pin-ok">${okLabel}</button>
          <button class="pin-cancel">Cancel</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    const errEl = overlay.querySelector('.lock-error');
    const field = overlay.querySelector('.pin-field');
    const confirmField = overlay.querySelector('.pin-confirm');
    field.focus();
    const cleanup = (result) => { overlay.remove(); resolve(result); };
    overlay.querySelector('.pin-cancel').addEventListener('click', () => cleanup(null));
    const submit = () => {
      const pin = field.value.trim();
      if (pin.length < 4){ errEl.textContent = 'PIN must be at least 4 digits.'; return; }
      if (needConfirm && confirmField.value.trim() !== pin){ errEl.textContent = "PINs don't match."; return; }
      cleanup(pin);
    };
    overlay.querySelector('.pin-ok').addEventListener('click', submit);
    overlay.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  });
}

/* ===================== App state ===================== */

const state = {
  notebook: null,
  cryptoKey: null,
  tool: 'pen',
  color: '#24314f',
  width: 2.2,
  fingerDraw: false,
  redoStack: [],   // per-page undo handled via notebook.pages[i]._undo/_redo (kept out of persisted copy)
  activeStroke: null,
  lasso: null,
  selection: []
};

const COLORS = ['#24314f', '#a4503a', '#3f6b4a', '#b08d57', '#efe7d8', '#000000'];

/* ===================== DOM refs ===================== */

const $ = (sel) => document.querySelector(sel);
const paperCanvas = $('#paper');
const inkCanvas = $('#ink');
const pageWrap = $('#pageWrap');
const paperCtx = paperCanvas.getContext('2d');
const inkCtx = inkCanvas.getContext('2d');

/* ===================== Sizing ===================== */

function sizeCanvases(){
  const rect = pageWrap.getBoundingClientRect();
  const dpr = Math.max(1, window.devicePixelRatio || 1);
  [paperCanvas, inkCanvas].forEach(c => {
    c.width = Math.round(rect.width * dpr);
    c.height = Math.round(rect.height * dpr);
  });
  paperCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
  inkCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
  renderPaper();
  renderInk();
}

/* ===================== Paper rendering ===================== */

function renderPaper(){
  const rect = pageWrap.getBoundingClientRect();
  const w = rect.width, h = rect.height;
  paperCtx.clearRect(0, 0, w, h);

  // paper base with a very subtle vignette
  paperCtx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--paper').trim();
  paperCtx.fillRect(0, 0, w, h);

  const grad = paperCtx.createRadialGradient(w/2, h*0.3, h*0.2, w/2, h/2, h*0.9);
  grad.addColorStop(0, 'rgba(0,0,0,0)');
  grad.addColorStop(1, 'rgba(0,0,0,0.035)');
  paperCtx.fillStyle = grad;
  paperCtx.fillRect(0, 0, w, h);

  const style = state.notebook.paperStyle;
  paperCtx.strokeStyle = 'rgba(90, 70, 30, 0.16)';
  paperCtx.lineWidth = 1;

  if (style === 'lined'){
    const gap = 34;
    for (let y = gap; y < h; y += gap){
      paperCtx.beginPath();
      paperCtx.moveTo(0, y + 0.5);
      paperCtx.lineTo(w, y + 0.5);
      paperCtx.stroke();
    }
  } else if (style === 'graph'){
    const gap = 26;
    for (let x = gap; x < w; x += gap){
      paperCtx.beginPath();
      paperCtx.moveTo(x + 0.5, 0);
      paperCtx.lineTo(x + 0.5, h);
      paperCtx.stroke();
    }
    for (let y = gap; y < h; y += gap){
      paperCtx.beginPath();
      paperCtx.moveTo(0, y + 0.5);
      paperCtx.lineTo(w, y + 0.5);
      paperCtx.stroke();
    }
  } else if (style === 'dot'){
    const gap = 26;
    paperCtx.fillStyle = 'rgba(90, 70, 30, 0.28)';
    for (let y = gap; y < h; y += gap){
      for (let x = gap; x < w; x += gap){
        paperCtx.beginPath();
        paperCtx.arc(x, y, 1, 0, Math.PI * 2);
        paperCtx.fill();
      }
    }
  }
}

/* ===================== Stroke rendering ===================== */

function strokePath(ctx, stroke){
  const pts = stroke.points;
  if (pts.length === 0) return;
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';

  if (stroke.tool === 'highlighter'){
    ctx.globalAlpha = 0.35;
    ctx.globalCompositeOperation = 'multiply';
  } else {
    ctx.globalAlpha = 1;
    ctx.globalCompositeOperation = 'source-over';
  }
  ctx.strokeStyle = stroke.color;

  if (pts.length === 1){
    const p = pts[0];
    ctx.beginPath();
    ctx.fillStyle = stroke.color;
    ctx.arc(p.x, p.y, (stroke.width * (p.p || 0.5)) / 2, 0, Math.PI * 2);
    ctx.fill();
    ctx.globalAlpha = 1;
    ctx.globalCompositeOperation = 'source-over';
    return;
  }

  for (let i = 1; i < pts.length; i++){
    const a = pts[i - 1], b = pts[i];
    const pressure = stroke.tool === 'highlighter' ? 1 : (((a.p||0.5) + (b.p||0.5)) / 2);
    ctx.lineWidth = Math.max(0.6, stroke.width * pressure);
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }
  ctx.globalAlpha = 1;
  ctx.globalCompositeOperation = 'source-over';
}

function renderInk(){
  const rect = pageWrap.getBoundingClientRect();
  inkCtx.clearRect(0, 0, rect.width, rect.height);
  const page = currentPage();
  if (!page) return;
  for (const s of page.strokes){
    strokePath(inkCtx, s);
  }
  if (state.activeStroke){
    strokePath(inkCtx, state.activeStroke);
  }
  if (state.lasso && state.lasso.length > 1){
    inkCtx.save();
    inkCtx.setLineDash([5, 4]);
    inkCtx.strokeStyle = 'rgba(176,141,87,0.9)';
    inkCtx.lineWidth = 1.4;
    inkCtx.beginPath();
    inkCtx.moveTo(state.lasso[0].x, state.lasso[0].y);
    for (const p of state.lasso.slice(1)) inkCtx.lineTo(p.x, p.y);
    inkCtx.stroke();
    inkCtx.restore();
  }
  for (const id of state.selection){
    const s = page.strokes.find(st => st.id === id);
    if (!s) continue;
    inkCtx.save();
    inkCtx.strokeStyle = 'rgba(176,141,87,0.9)';
    inkCtx.lineWidth = (s.width + 6);
    inkCtx.globalAlpha = 0.22;
    inkCtx.lineCap = 'round'; inkCtx.lineJoin = 'round';
    inkCtx.beginPath();
    s.points.forEach((p, i) => i === 0 ? inkCtx.moveTo(p.x,p.y) : inkCtx.lineTo(p.x,p.y));
    inkCtx.stroke();
    inkCtx.restore();
  }
}

/* ===================== Page helpers ===================== */

function currentPage(){
  if (!state.notebook) return null;
  return state.notebook.pages[state.notebook.currentPageIndex];
}

function pushHistory(page, action){
  page._undo = page._undo || [];
  page._redo = [];
  page._undo.push(action);
  if (page._undo.length > 80) page._undo.shift();
}

function undo(){
  const page = currentPage();
  if (!page || !page._undo || !page._undo.length) return;
  const action = page._undo.pop();
  page._redo = page._redo || [];
  page._redo.push(action);
  applyInverse(page, action);
  renderInk();
  saveNotebook();
}
function redo(){
  const page = currentPage();
  if (!page || !page._redo || !page._redo.length) return;
  const action = page._redo.pop();
  page._undo = page._undo || [];
  page._undo.push(action);
  applyForward(page, action);
  renderInk();
  saveNotebook();
}
function applyInverse(page, action){
  if (action.type === 'add'){
    page.strokes = page.strokes.filter(s => s.id !== action.stroke.id);
  } else if (action.type === 'remove'){
    page.strokes.splice(Math.min(action.index, page.strokes.length), 0, action.stroke);
  }
}
function applyForward(page, action){
  if (action.type === 'add'){
    page.strokes.push(action.stroke);
  } else if (action.type === 'remove'){
    page.strokes = page.strokes.filter(s => s.id !== action.stroke.id);
  }
}

function addStroke(stroke){
  const page = currentPage();
  page.strokes.push(stroke);
  pushHistory(page, { type: 'add', stroke });
}
function removeStroke(id){
  const page = currentPage();
  const idx = page.strokes.findIndex(s => s.id === id);
  if (idx === -1) return;
  const [stroke] = page.strokes.splice(idx, 1);
  pushHistory(page, { type: 'remove', stroke, index: idx });
}

/* ===================== Drawing input ===================== */

let drawing = false;
let erasing = false;
let lassoing = false;

function localPoint(e){
  const rect = inkCanvas.getBoundingClientRect();
  return { x: e.clientX - rect.left, y: e.clientY - rect.top, p: e.pressure > 0 ? e.pressure : 0.5 };
}

function pointInPolygon(pt, poly){
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++){
    const xi = poly[i].x, yi = poly[i].y, xj = poly[j].x, yj = poly[j].y;
    const intersect = ((yi > pt.y) !== (yj > pt.y)) &&
      (pt.x < (xj - xi) * (pt.y - yi) / (yj - yi + 0.0000001) + xi);
    if (intersect) inside = !inside;
  }
  return inside;
}

function strokeNear(page, pt, radius){
  for (let i = page.strokes.length - 1; i >= 0; i--){
    const s = page.strokes[i];
    for (const p of s.points){
      if (Math.hypot(p.x - pt.x, p.y - pt.y) <= radius) return s;
    }
  }
  return null;
}

inkCanvas.addEventListener('pointerdown', (e) => {
  if (e.pointerType === 'touch' && !state.fingerDraw) return;
  inkCanvas.setPointerCapture(e.pointerId);
  const pt = localPoint(e);

  if (state.tool === 'pen' || state.tool === 'highlighter'){
    drawing = true;
    state.activeStroke = {
      id: uid(),
      tool: state.tool,
      color: state.color,
      width: state.tool === 'highlighter' ? state.width * 4 : state.width,
      points: [pt]
    };
  } else if (state.tool === 'eraser'){
    erasing = true;
    const hit = strokeNear(currentPage(), pt, 14);
    if (hit) removeStroke(hit.id);
    renderInk();
    saveNotebookDebounced();
  } else if (state.tool === 'lasso'){
    lassoing = true;
    state.lasso = [pt];
    state.selection = [];
  }
}, { passive: true });

inkCanvas.addEventListener('pointermove', (e) => {
  if (e.pointerType === 'touch' && !state.fingerDraw) return;
  const points = (e.getCoalescedEvents && e.getCoalescedEvents().length) ? e.getCoalescedEvents() : [e];

  if (drawing && state.activeStroke){
    for (const ev of points) state.activeStroke.points.push(localPoint(ev));
    renderInk();
  } else if (erasing){
    const pt = localPoint(e);
    const hit = strokeNear(currentPage(), pt, 14);
    if (hit) { removeStroke(hit.id); renderInk(); }
  } else if (lassoing){
    const pt = localPoint(e);
    state.lasso.push(pt);
    renderInk();
  }
}, { passive: true });

function endStroke(){
  if (drawing && state.activeStroke){
    if (state.activeStroke.points.length){
      addStroke(state.activeStroke);
    }
    state.activeStroke = null;
    drawing = false;
    renderInk();
    saveNotebookDebounced();
  }
  if (erasing){
    erasing = false;
    saveNotebookDebounced();
  }
  if (lassoing){
    lassoing = false;
    const page = currentPage();
    if (state.lasso && state.lasso.length > 2){
      state.selection = page.strokes
        .filter(s => s.points.some(p => pointInPolygon(p, state.lasso)))
        .map(s => s.id);
    }
    state.lasso = null;
    renderInk();
    if (state.selection.length) showSelectionBar(); else hideSelectionBar();
  }
}
inkCanvas.addEventListener('pointerup', endStroke);
inkCanvas.addEventListener('pointercancel', endStroke);
inkCanvas.addEventListener('pointerleave', (e) => { if (e.pointerType !== 'touch') endStroke(); });

/* Floating delete pill for lasso selection */
let selBar = null;
function showSelectionBar(){
  hideSelectionBar();
  selBar = document.createElement('button');
  selBar.textContent = `Delete ${state.selection.length} stroke${state.selection.length > 1 ? 's' : ''}`;
  Object.assign(selBar.style, {
    position: 'fixed', left: '50%', bottom: 'calc(var(--dock-h) + 14px)',
    transform: 'translateX(-50%)', zIndex: 40,
    background: '#a4503a', color: '#fff', border: 'none',
    padding: '10px 16px', borderRadius: '20px', fontSize: '13px',
    boxShadow: '0 8px 20px rgba(0,0,0,.4)'
  });
  selBar.addEventListener('click', () => {
    const page = currentPage();
    for (const id of state.selection) removeStroke(id);
    state.selection = [];
    renderInk();
    saveNotebookDebounced();
    hideSelectionBar();
  });
  document.body.appendChild(selBar);
}
function hideSelectionBar(){
  if (selBar){ selBar.remove(); selBar = null; }
}

/* ===================== Persistence ===================== */

function stripTransient(notebook){
  return {
    ...notebook,
    pages: notebook.pages.map(p => ({ id: p.id, strokes: p.strokes }))
  };
}

let saveTimer = null;
function saveNotebookDebounced(){
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveNotebook, 350);
}
async function saveNotebook(){
  if (!state.notebook) return;
  state.notebook.updatedAt = Date.now();
  const plain = stripTransient(state.notebook);
  const rec = state.cryptoKey ? await encryptNotebookRecord(plain, state.cryptoKey) : plain;
  await idbPut('notebooks', rec);
  await idbPut('meta', { key: 'activeNotebookId', value: state.notebook.id });
}

async function loadInitialNotebook(){
  const meta = await idbGet('meta', 'activeNotebookId');
  let rec = null;
  if (meta && meta.value){
    rec = await idbGet('notebooks', meta.value);
  }
  if (!rec){
    const all = await idbAll('notebooks');
    rec = all.sort((a,b) => b.updatedAt - a.updatedAt)[0];
  }
  if (rec){
    state.notebook = await decryptNotebookRecord(rec);
    return;
  }
  const nb = newNotebook('My Notebook');
  const toStore = state.cryptoKey ? await encryptNotebookRecord(nb, state.cryptoKey) : nb;
  await idbPut('notebooks', toStore);
  await idbPut('meta', { key: 'activeNotebookId', value: nb.id });
  state.notebook = nb;
}

/* ===================== UI wiring ===================== */

function renderTopbar(){
  $('#notebookTitle').textContent = state.notebook.name;
  $('#pageCount').textContent = `${state.notebook.currentPageIndex + 1} / ${state.notebook.pages.length}`;
  renderSpineStitches();
  document.querySelectorAll('.paper-opt').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.paper === state.notebook.paperStyle);
  });
}

function renderSpineStitches(){
  const el = $('#spineStitches');
  el.innerHTML = '';
  const total = state.notebook.pages.length;
  const cur = state.notebook.currentPageIndex;
  const max = 24;
  const count = Math.min(total, max);
  for (let i = 0; i < count; i++){
    const dot = document.createElement('div');
    dot.className = 'stitch' + (i === Math.round((cur / Math.max(1,total-1)) * (count-1)) ? ' current' : '');
    el.appendChild(dot);
  }
}

function goToPage(i){
  const page = currentPage();
  if (page){ delete page._undo; delete page._redo; }
  state.notebook.currentPageIndex = Math.max(0, Math.min(state.notebook.pages.length - 1, i));
  state.selection = [];
  hideSelectionBar();
  renderTopbar();
  renderPaper();
  renderInk();
  saveNotebook();
}

function addPage(){
  state.notebook.pages.splice(state.notebook.currentPageIndex + 1, 0, blankPage());
  goToPage(state.notebook.currentPageIndex + 1);
}

function initSwatches(){
  const wrap = $('#swatches');
  wrap.innerHTML = '';
  COLORS.forEach(c => {
    const b = document.createElement('button');
    b.className = 'swatch' + (c === state.color ? ' active' : '');
    b.style.background = c;
    b.addEventListener('click', () => {
      state.color = c;
      document.querySelectorAll('.swatch').forEach(s => s.classList.remove('active'));
      b.classList.add('active');
    });
    wrap.appendChild(b);
  });
  const custom = document.createElement('input');
  custom.type = 'color';
  custom.className = 'swatch custom';
  custom.value = state.color;
  custom.style.padding = '0';
  custom.addEventListener('input', () => {
    state.color = custom.value;
    document.querySelectorAll('.swatch').forEach(s => s.classList.remove('active'));
  });
  wrap.appendChild(custom);
}

function initTools(){
  document.querySelectorAll('.tool-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tool-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.tool = btn.dataset.tool;
      state.selection = [];
      hideSelectionBar();
      renderInk();
    });
  });
}

function openOverlay(id){ $(id).classList.add('open'); }
function closeOverlay(id){ $(id).classList.remove('open'); }

function renderPagesGrid(){
  const grid = $('#pagesGrid');
  grid.innerHTML = '';
  state.notebook.pages.forEach((p, i) => {
    const btn = document.createElement('button');
    btn.className = 'page-thumb' + (i === state.notebook.currentPageIndex ? ' current' : '');
    const img = document.createElement('img');
    img.src = thumbForPage(p);
    btn.appendChild(img);
    const num = document.createElement('span');
    num.className = 'thumb-num';
    num.textContent = i + 1;
    btn.appendChild(num);
    if (state.notebook.pages.length > 1){
      const del = document.createElement('button');
      del.className = 'thumb-del';
      del.textContent = '✕';
      del.addEventListener('click', (ev) => {
        ev.stopPropagation();
        deletePageAt(i);
        renderPagesGrid();
      });
      btn.appendChild(del);
    }
    btn.addEventListener('click', () => { goToPage(i); closeOverlay('#pagesOverlay'); });
    grid.appendChild(btn);
  });
}

function thumbForPage(page){
  const c = document.createElement('canvas');
  const w = 160, h = 213;
  c.width = w; c.height = h;
  const ctx = c.getContext('2d');
  ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--paper').trim();
  ctx.fillRect(0,0,w,h);
  const rect = pageWrap.getBoundingClientRect();
  const sx = w / rect.width, sy = h / rect.height;
  ctx.save();
  ctx.scale(sx, sy);
  for (const s of page.strokes) strokePath(ctx, s);
  ctx.restore();
  return c.toDataURL('image/png');
}

function deletePageAt(i){
  if (state.notebook.pages.length <= 1) return;
  state.notebook.pages.splice(i, 1);
  if (state.notebook.currentPageIndex >= state.notebook.pages.length){
    state.notebook.currentPageIndex = state.notebook.pages.length - 1;
  }
  goToPage(state.notebook.currentPageIndex);
}

async function renderLibrary(){
  const list = $('#libraryList');
  list.innerHTML = '<div class="menu-footer">Loading…</div>';
  const allRecs = await idbAll('notebooks');
  const all = [];
  for (const rec of allRecs) all.push(await decryptNotebookRecord(rec));
  all.sort((a,b) => b.updatedAt - a.updatedAt);
  list.innerHTML = '';
  all.forEach(nb => {
    const item = document.createElement('button');
    item.className = 'library-item' + (nb.id === state.notebook.id ? ' current' : '');
    const icon = document.createElement('div'); icon.className = 'lib-icon';
    const meta = document.createElement('div'); meta.className = 'lib-meta';
    const name = document.createElement('div'); name.className = 'lib-name'; name.textContent = nb.name;
    const sub = document.createElement('div'); sub.className = 'lib-sub';
    sub.textContent = `${nb.pages.length} page${nb.pages.length !== 1 ? 's' : ''} · ${new Date(nb.updatedAt).toLocaleDateString()}`;
    meta.appendChild(name); meta.appendChild(sub);
    item.appendChild(icon); item.appendChild(meta);
    if (all.length > 1){
      const del = document.createElement('button');
      del.className = 'lib-del'; del.textContent = '✕';
      del.addEventListener('click', async (ev) => {
        ev.stopPropagation();
        if (nb.id === state.notebook.id) return;
        await idbDelete('notebooks', nb.id);
        renderLibrary();
      });
      item.appendChild(del);
    }
    item.addEventListener('click', async () => {
      state.notebook = nb;
      await idbPut('meta', { key: 'activeNotebookId', value: nb.id });
      goToPage(nb.currentPageIndex || 0);
      closeOverlay('#libraryOverlay');
    });
    list.appendChild(item);
  });
}

/* ===================== Event wiring ===================== */

function wireUI(){
  $('#prevPage').addEventListener('click', () => goToPage(state.notebook.currentPageIndex - 1));
  $('#nextPage').addEventListener('click', () => {
    if (state.notebook.currentPageIndex === state.notebook.pages.length - 1) addPage();
    else goToPage(state.notebook.currentPageIndex + 1);
  });
  $('#addPage').addEventListener('click', addPage);

  $('#undoBtn').addEventListener('click', undo);
  $('#redoBtn').addEventListener('click', redo);

  $('#widthSlider').addEventListener('input', (e) => { state.width = parseFloat(e.target.value); });

  $('#pagesBtn').addEventListener('click', () => { renderPagesGrid(); openOverlay('#pagesOverlay'); });
  $('#closePagesOverlay').addEventListener('click', () => closeOverlay('#pagesOverlay'));

  $('#libraryBtn').addEventListener('click', () => { renderLibrary(); openOverlay('#libraryOverlay'); });
  $('#closeLibraryOverlay').addEventListener('click', () => closeOverlay('#libraryOverlay'));
  $('#newNotebookBtn').addEventListener('click', async () => {
    const nb = newNotebook('Untitled Notebook');
    const toStore = state.cryptoKey ? await encryptNotebookRecord(nb, state.cryptoKey) : nb;
    await idbPut('notebooks', toStore);
    state.notebook = nb;
    await idbPut('meta', { key: 'activeNotebookId', value: nb.id });
    goToPage(0);
    closeOverlay('#libraryOverlay');
  });

  $('#menuBtn').addEventListener('click', async () => { await renderSecurityMenu(); openOverlay('#menuOverlay'); });
  $('#closeMenuOverlay').addEventListener('click', () => closeOverlay('#menuOverlay'));

  document.querySelectorAll('.paper-opt').forEach(btn => {
    btn.addEventListener('click', () => {
      state.notebook.paperStyle = btn.dataset.paper;
      renderTopbar();
      renderPaper();
      saveNotebookDebounced();
    });
  });

  $('#fingerDrawToggle').addEventListener('change', (e) => { state.fingerDraw = e.target.checked; });

  $('#notebookTitleBtn').addEventListener('click', () => {
    const name = prompt('Notebook name', state.notebook.name);
    if (name && name.trim()){
      state.notebook.name = name.trim();
      renderTopbar();
      saveNotebookDebounced();
    }
  });
  $('#renameNotebookBtn').addEventListener('click', () => {
    closeOverlay('#menuOverlay');
    $('#notebookTitleBtn').click();
  });

  $('#clearPageBtn').addEventListener('click', () => {
    if (!confirm('Clear all drawing on this page?')) return;
    const page = currentPage();
    page.strokes = [];
    delete page._undo; delete page._redo;
    renderInk();
    saveNotebookDebounced();
    closeOverlay('#menuOverlay');
  });
  $('#deletePageBtn').addEventListener('click', () => {
    if (state.notebook.pages.length <= 1){ alert("This is the only page — can't delete it."); return; }
    if (!confirm('Delete this page?')) return;
    deletePageAt(state.notebook.currentPageIndex);
    closeOverlay('#menuOverlay');
  });

  $('#exportPageBtn').addEventListener('click', () => {
    const rect = pageWrap.getBoundingClientRect();
    const c = document.createElement('canvas');
    const dpr = Math.max(1, window.devicePixelRatio || 1);
    c.width = rect.width * dpr; c.height = rect.height * dpr;
    const ctx = c.getContext('2d');
    ctx.drawImage(paperCanvas, 0, 0);
    ctx.drawImage(inkCanvas, 0, 0);
    const a = document.createElement('a');
    a.download = `${state.notebook.name.replace(/\s+/g,'_')}_page${state.notebook.currentPageIndex+1}.png`;
    a.href = c.toDataURL('image/png');
    a.click();
    closeOverlay('#menuOverlay');
  });

  window.addEventListener('resize', sizeCanvases);

  $('#enableLockBtn').addEventListener('click', async () => {
    closeOverlay('#menuOverlay');
    const pin = await askPin({
      title: 'Set up a PIN',
      subtitle: 'This encrypts your notebooks with AES-256 on this device.',
      needConfirm: true,
      okLabel: 'Enable lock'
    });
    if (!pin) return;
    await enableLock(pin);
    alert('PIN lock enabled. Your notebooks are now encrypted on this device.');
  });

  $('#lockNowBtn').addEventListener('click', () => {
    closeOverlay('#menuOverlay');
    location.reload();
  });

  $('#changePinBtn').addEventListener('click', async () => {
    closeOverlay('#menuOverlay');
    const oldPin = await askPin({ title: 'Current PIN', subtitle: 'Enter your current PIN to continue.', okLabel: 'Next' });
    if (!oldPin) return;
    const ok = await tryUnlock(oldPin);
    if (!ok){ alert('Incorrect PIN.'); return; }
    const newPin = await askPin({ title: 'New PIN', subtitle: 'Choose a new PIN.', needConfirm: true, okLabel: 'Save' });
    if (!newPin) return;
    await enableLock(newPin);
    alert('PIN changed.');
  });

  $('#disableLockBtn').addEventListener('click', async () => {
    closeOverlay('#menuOverlay');
    const pin = await askPin({ title: 'Turn off lock', subtitle: 'Enter your PIN to confirm and decrypt your notebooks.', okLabel: 'Turn off' });
    if (!pin) return;
    const ok = await tryUnlock(pin);
    if (!ok){ alert('Incorrect PIN.'); return; }
    await disableLock();
    alert('Lock turned off. Notebooks are now stored unencrypted on this device.');
  });

  // simple horizontal swipe between pages on the stage (two-finger or mouse-free zones)
  let touchStartX = null;
  $('#stage').addEventListener('touchstart', (e) => {
    if (e.touches.length === 1 && state.tool !== 'lasso') touchStartX = null; // avoid clashing with drawing
  }, { passive: true });
}

async function renderSecurityMenu(){
  const sec = await idbGet('meta', 'security');
  const enabled = !!(sec && sec.value && sec.value.enabled);
  $('#enableLockBtn').style.display = enabled ? 'none' : 'block';
  $('#lockNowBtn').style.display = enabled ? 'block' : 'none';
  $('#changePinBtn').style.display = enabled ? 'block' : 'none';
  $('#disableLockBtn').style.display = enabled ? 'block' : 'none';
  $('#storageInfo').textContent = enabled
    ? 'Encrypted on this device with your PIN'
    : 'Saved on this iPad (not encrypted)';
}

/* ===================== Boot ===================== */

async function continueBoot(){
  await loadInitialNotebook();
  initSwatches();
  initTools();
  wireUI();
  renderTopbar();
  sizeCanvases();

  if ('serviceWorker' in navigator){
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
}

function showLockScreen(){
  const screen = $('#lockScreen');
  const input = $('#lockPinInput');
  const err = $('#lockError');
  screen.style.display = 'flex';
  input.focus();
  const attempt = async () => {
    const pin = input.value.trim();
    if (!pin) return;
    const ok = await tryUnlock(pin);
    if (ok){
      screen.style.display = 'none';
      err.textContent = '';
      await continueBoot();
    } else {
      err.textContent = 'Incorrect PIN. Try again.';
      input.value = '';
      input.focus();
    }
  };
  $('#lockUnlockBtn').addEventListener('click', attempt);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') attempt(); });
}

async function boot(){
  const sec = await idbGet('meta', 'security');
  if (sec && sec.value && sec.value.enabled){
    showLockScreen();
  } else {
    await continueBoot();
  }
}

boot();
