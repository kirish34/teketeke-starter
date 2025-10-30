// ===== TekeTeke Admin Console (CSP-safe) =====

let UI_USSD_ROOT = '123';
const $ = (id) => document.getElementById(id);

const sectionMap = {
  register: 'section-register',
  edit: 'section-edit',
  list: 'section-list',
  transactions: 'section-transactions',
  session: 'section-session'
};

function buttonKey(btn) {
  if (!btn) return null;
  if (btn.dataset.section) return btn.dataset.section;
  if (btn.id) {
    let derived = btn.id.replace(/^nav-/, '');
    if (derived === 'trans') derived = 'transactions';
    return derived;
  }
  return null;
}

function showSection(key, { updateHash = true } = {}) {
  if (!sectionMap[key]) key = 'register';
  if (updateHash && location.hash !== `#${key}`) {
    location.hash = key;
  }
  document.querySelectorAll('.section').forEach(section => {
    section.classList.toggle('active', section.id === sectionMap[key]);
  });
  document.querySelectorAll('.nav button').forEach(btn => {
    const btnKey = buttonKey(btn);
    btn.classList.toggle('active', btnKey === key);
  });
  if (key === 'list') {
    loadMatatus().catch(() => {});
  } else if (key === 'transactions') {
    loadTransactions().catch(() => {});
  }
}

function syncFromHash() {
  const key = (location.hash || '#register').slice(1);
  showSection(key, { updateHash: false });
}

function initNav() {
  const nav = document.querySelector('.nav');
  if (!nav) return;
  nav.addEventListener('click', (event) => {
    const btn = event.target.closest('button');
    if (!btn || !nav.contains(btn)) return;
    const key = buttonKey(btn);
    if (!key) return;
    btn.dataset.section = key;
    event.preventDefault();
    showSection(key);
  });
  nav.querySelectorAll('button').forEach(btn => {
    const key = buttonKey(btn);
    if (key) btn.dataset.section = key;
    btn.type = 'button';
  });
}

function initRouter() {
  syncFromHash();
  window.addEventListener('hashchange', syncFromHash);
}

function showToast(msg) {
  const t = $('toast');
  t.textContent = msg || 'Done';
  t.classList.add('show');
  clearTimeout(window.__toast);
  window.__toast = setTimeout(() => t.classList.remove('show'), 1200);
}

async function api(path, opts = {}) {
  const headers = { 'content-type': 'application/json', ...(opts.headers || {}) };
  const request = { credentials: 'include', ...opts, headers };
  const res = await fetch(path, request);
  if (res.status === 401) {
    window.location.href = '/login.html';
    throw new Error('unauthorized');
  }
  const requestId = res.headers.get('x-request-id');
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body.error || res.statusText || 'request_failed');
    err.requestId = body.request_id || requestId || null;
    throw err;
  }
  if (body && typeof body === 'object' && !Array.isArray(body) && requestId && !body.request_id) {
    body.request_id = requestId;
  }
  return body;
}

async function ensureAuth(){
  const res = await fetch('/api/auth/me', { credentials: 'include' });
  if (!res.ok) { window.location.href = '/login.html'; return false; }
  return true;
}

async function fetchConfig(){
  try {
    const cfg = await api('/api/config');
    if (cfg && cfg.ussd_root) UI_USSD_ROOT = String(cfg.ussd_root);
  } catch (_) {}
}

async function logout(event){
  if (event) event.preventDefault();
  try { await fetch('/api/auth/logout', { method:'POST', credentials:'include' }); } catch(_){ }
  window.location.href = '/login.html';
}

async function createMatatu(e){
  e.preventDefault();
  const plate = $('new_plate').value.trim();
  const name = $('new_name').value.trim();
  const sacco_name = $('new_sacco').value.trim();
  const till = $('new_till').value.trim();
  if(!plate || !till){ showToast('Plate & till required'); return false; }

  const out = await api('/api/matatus', { method:'POST', body: JSON.stringify({ plate, name, sacco_name }) });
  const id = out.matatu.id;

  await api(`/api/matatus/${id}/till`, { method:'POST', body: JSON.stringify({ till_number: till }) });
  const alloc = await api(`/api/matatus/${id}/ussd`, { method:'POST' });

  showToast(`Saved - Till ${till} - ${alloc.dial}`);
  $('new_plate').value = ''; $('new_name').value = ''; $('new_sacco').value = ''; $('new_till').value = '';
  await loadMatatus();
  return false;
}

let _matatus = [];
let _matatuTotal = 0;
let _transactions = [];
let _lastTxSummary = null;
let _listFilterTimer = null;
async function loadMatatus(options = {}){
  const plate = options.plate ? String(options.plate).trim() : '';
  const endpoint = plate ? `/api/matatus/search?plate=${encodeURIComponent(plate)}` : '/api/matatus';
  const out = await api(endpoint);
  const items = out.items || [];
  const total = out.meta && typeof out.meta.total === 'number' ? out.meta.total : items.length;
  if (!plate) {
    _matatus = items;
    _matatuTotal = total;
    refreshMatatuOptions();
  }
  const overall = plate ? (_matatuTotal || total) : total;
  renderList(items, { totalCount: items.length, overallCount: overall });
  return items;
}

function scheduleListFilter(){
  if (_listFilterTimer) clearTimeout(_listFilterTimer);
  _listFilterTimer = setTimeout(() => {
    const q = $('list_filter').value.trim();
    if (!q) {
      loadMatatus().catch(() => {});
    } else {
      loadMatatus({ plate: q }).catch(() => {});
    }
  }, 200);
}

function renderList(items, context = {}){
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = '';
  const totalEl = $('list_total');
  if (totalEl) {
    const totalCount =
      typeof context.totalCount === 'number' && !Number.isNaN(context.totalCount) ? context.totalCount : items.length;
    const overall =
      typeof context.overallCount === 'number' && !Number.isNaN(context.overallCount)
        ? context.overallCount
        : totalCount;
    if (overall <= totalCount) {
      totalEl.textContent = `Total: ${formatNumber(overall)}`;
    } else {
      totalEl.textContent = `Showing ${formatNumber(totalCount)} of ${formatNumber(overall)}`;
    }
  }
  if (items.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 7;
    td.className = 'muted';
    td.textContent = 'No matatus found.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    if (totalEl && !context.totalCount && !context.overallCount) {
      totalEl.textContent = 'Total: 0';
    }
    return;
  }
  items.forEach(x=>{
    const tr = document.createElement('tr');
    tr.dataset.matatuId = x.matatu_id || '';
    tr.dataset.plate = x.plate || '';
    tr.style.cursor = 'pointer';
    tr.title = 'View transactions';
    tr.addEventListener('click', (ev) => {
      if (ev.target.closest('button')) return;
      focusTransactions(x);
    });

    const tdDial = document.createElement('td'); tdDial.className='mono';
    const dial = x.ussd_code ? (`*${UI_USSD_ROOT}*${x.ussd_code}#`) : '';
    if (dial) {
      const span = document.createElement('span'); span.textContent = dial;
      const btn = document.createElement('button'); btn.className='copybtn'; btn.type='button'; btn.textContent='Copy';
      btn.addEventListener('click', ()=> navigator.clipboard.writeText(dial).then(()=>showToast('Copied')));
      tdDial.append(span, btn);
    }

    tr.append(
      cell(x.matatu_id, true),
      cell(x.plate, true),
      cell(x.till_number, true),
      cell(x.ussd_code, true),
      tdDial,
      cell(x.total_success || 0),
      cell(x.last_tx_at || '', true)
    );
    tbody.appendChild(tr);
  });
}

function refreshMatatuOptions(){
  const select = $('tx_matatu');
  if (!select) return;
  const current = select.value;
  select.innerHTML = '';
  const baseOpt = document.createElement('option');
  baseOpt.value = '';
  baseOpt.textContent = 'All matatus';
  select.appendChild(baseOpt);
  _matatus.forEach((m) => {
    const opt = document.createElement('option');
    opt.value = m.matatu_id || '';
    const parts = [];
    if (m.plate) parts.push(m.plate);
    if (m.till_number) parts.push(`Till ${m.till_number}`);
    opt.textContent = parts.length ? parts.join(' • ') : (m.matatu_id || 'Unknown matatu');
    select.appendChild(opt);
  });
  if (current && Array.from(select.options).some((opt) => opt.value === current)) {
    select.value = current;
  } else {
    select.value = '';
  }
}

function focusTransactions(matatu){
  const select = $('tx_matatu');
  if (select && matatu && matatu.matatu_id) {
    if (!Array.from(select.options).some((opt) => opt.value === matatu.matatu_id)) {
      refreshMatatuOptions();
    }
    select.value = matatu.matatu_id;
  }
  const plateInput = $('tx_plate');
  if (plateInput) plateInput.value = '';
  const fromInput = $('tx_from');
  const toInput = $('tx_to');
  if (fromInput) fromInput.value = '';
  if (toInput) toInput.value = '';
  location.hash = '#transactions';
}

function cell(text, mono=false){
  const td = document.createElement('td'); if(mono) td.className='mono'; td.textContent = text || ''; return td;
}

async function changeTill(x){
  const next = prompt(`Enter new till for ${x.plate}`, x.till_number || '');
  if(next == null) return;
  const t = next.trim(); if(!t || t === x.till_number) return;
  await api(`/api/matatus/${x.matatu_id}/till`, { method:'POST', body: JSON.stringify({ till_number: t }) });
  showToast('Till updated'); await loadMatatus();
}

async function reassignUssd(matatuId, plate){
  if (!matatuId) return;
  if (!confirm(`Assign a new USSD code for ${plate || 'this matatu'}?`)) return;
  const out = await api(`/api/matatus/${matatuId}/ussd/reassign`, { method:'POST' });
  showToast(`New USSD ${out.dial}`); await loadMatatus();
}

async function deleteMatatu(matatuId, plate){
  if (!matatuId) return;
  if (!confirm(`Delete matatu ${plate || ''}? This cannot be undone.`)) return;
  await api(`/api/matatus/${matatuId}`, { method:'DELETE' });
  showToast('Matatu deleted'); await loadMatatus();
}

async function searchMatatu(){
  const raw = $('edit_search').value.trim();
  if(!raw){
    $('edit_result').innerHTML = '<span class="muted">Enter a plate.</span>';
    return;
  }
  const out = await api(`/api/matatus/search?plate=${encodeURIComponent(raw)}`);
  const items = out.items || [];
  if (!items.length) {
    $('edit_result').innerHTML = 'No match.';
    return;
  }
  const target = raw.replace(/\s+/g, '').toUpperCase();
  const exact = items.find((x) => ((x.plate || '').replace(/\s+/g, '').toUpperCase()) === target);
  renderEdit(exact || items[0]);
}

function renderEdit(x){
  const dial = x.ussd_code ? (`*${UI_USSD_ROOT}*${x.ussd_code}#`) : '';
  $('edit_result').innerHTML = `
    <div class="row" style="margin-bottom:8px">
      <div class="card">
        <div class="mono muted">Matatu ID</div>
        <div class="mono">${x.matatu_id}</div>
        <div class="mono muted" style="margin-top:8px">Plate</div>
        <div class="mono">${x.plate || ''}</div>
      </div>
      <div class="card">
        <div class="mono muted">Till Number</div>
        <div class="mono" id="ed_till">${x.till_number || ''}</div>
        <div class="mono muted" style="margin-top:8px">USSD Code</div>
        <div class="mono">${x.ussd_code || ''} ${dial ? `- ${dial}` : ''}</div>
      </div>
    </div>
    <div class="actions">
      <button id="btn-ed-till" class="secondary" type="button">Edit Till</button>
      <button id="btn-ed-ussd" class="secondary" type="button">New USSD</button>
      <button id="btn-ed-del" class="danger" type="button">Delete</button>
    </div>
  `;
  $('btn-ed-till').addEventListener('click', () => editChangeTill(x.matatu_id, x.plate || '', x.till_number || ''));
  $('btn-ed-ussd').addEventListener('click', async () => { await reassignUssd(x.matatu_id, x.plate || ''); searchMatatu(); });
  $('btn-ed-del').addEventListener('click', async () => { await deleteMatatu(x.matatu_id, x.plate || ''); $('edit_result').innerHTML='Deleted'; });
}

async function editChangeTill(id, plate, current){
  const next = prompt(`Enter new till for ${plate}`, current || '');
  if(next == null) return;
  const t = next.trim(); if(!t || t === current) return;
  await api(`/api/matatus/${id}/till`, { method:'POST', body: JSON.stringify({ till_number: t }) });
  showToast('Till updated'); searchMatatu();
}

async function loadTransactions(){
  const hint = $('tx_hint');
  const table = $('tx_tbl');
  const tbody = table.querySelector('tbody');
  const summaryEl = $('tx_summary');
  if (!hint || !table || !tbody) return;

  if (summaryEl) {
    summaryEl.style.display = 'none';
    summaryEl.textContent = '';
  }
  hint.style.display = 'block';
  hint.textContent = 'Loading transactions...';
  table.style.display = 'none';
  tbody.innerHTML = '';

  const params = new URLSearchParams();
  const plateQuery = ($('tx_plate')?.value || '').trim();
  const matatuId = $('tx_matatu')?.value || '';
  const fromVal = $('tx_from')?.value || '';
  const toVal = $('tx_to')?.value || '';

  if (fromVal && toVal && fromVal > toVal) {
    hint.textContent = 'From date must be before To date.';
    showToast('From date must be before To date');
    return;
  }

  if (matatuId) params.set('matatu_id', matatuId);
  if (plateQuery) params.set('plate', plateQuery);
  if (fromVal) params.set('from', fromVal);
  if (toVal) params.set('to', toVal);
  const url = params.toString() ? `/api/transactions?${params.toString()}` : '/api/transactions';
  const selectedMatatu = matatuId ? _matatus.find((m) => m.matatu_id === matatuId) : null;

  try {
    const out = await api(url);
    _transactions = out.items || [];
    const summary = out.summary || { total: _transactions.length, total_today: 0 };
    _lastTxSummary = summary;
    renderTransactions(_transactions);
    updateTransactionsSummary(summary, {
      matatu: selectedMatatu,
      filters: { from: fromVal, to: toVal, plate: plateQuery }
    });
  } catch (err) {
    updateTransactionsSummary(null);
    hint.style.display = 'block';
    hint.textContent = 'Failed to load transactions.';
    showToast(err.message || 'Failed to load transactions');
  }
}

function renderTransactions(items){
  const hint = $('tx_hint');
  const table = $('tx_tbl');
  const tbody = table.querySelector('tbody');
  if (!hint || !table || !tbody) return;

  tbody.innerHTML = '';
  if (!items.length) {
    hint.style.display = 'block';
    hint.textContent = 'No transactions found.';
    table.style.display = 'none';
    return;
  }

  hint.style.display = 'none';
  table.style.display = 'table';

  items.forEach((tx) => {
    const tr = document.createElement('tr');
    tr.append(
      cell(formatDateTime(tx.created_at), true),
      cell((tx.matatu && tx.matatu.plate) || '', true),
      cell(tx.msisdn || ''),
      cell(formatAmount(tx.amount), true),
      statusCell(tx.status),
      cell(tx.mpesa_receipt || tx.gateway_ref || '')
    );
    tbody.appendChild(tr);
  });
}

function formatAmount(value){
  const num = Number(value);
  if (!Number.isFinite(num)) return 'KES 0.00';
  const formatted = num.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `KES ${formatted}`;
}

function formatDateTime(iso){
  if (!iso) return '';
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return iso;
  return dt.toLocaleString();
}

function statusCell(status){
  const td = document.createElement('td');
  const span = document.createElement('span');
  const value = String(status || '').toLowerCase();
  span.className = 'pill';
  if (value) {
    const slug = value.replace(/[^a-z0-9-]/g, '');
    if (slug) span.classList.add(`pill-${slug}`);
  }
  span.textContent = value ? value.charAt(0).toUpperCase() + value.slice(1) : '';
  td.appendChild(span);
  return td;
}

function updateTransactionsSummary(summary, context = {}) {
  const summaryEl = $('tx_summary');
  if (!summaryEl) return;
  if (!summary) {
    summaryEl.style.display = 'none';
    summaryEl.textContent = '';
    return;
  }
  const total = formatNumber(summary.total);
  const today = formatNumber(summary.total_today);
  const parts = [];
  if (context.matatu && (context.matatu.plate || context.matatu.matatu_id)) {
    parts.push(`Matatu ${context.matatu.plate || context.matatu.matatu_id}`);
  } else if (context.filters && context.filters.plate) {
    parts.push(`Plate like "${context.filters.plate}"`);
  }
  if (context.filters) {
    const { from, to } = context.filters;
    if (from && to) parts.push(`Range ${from} → ${to}`);
    else if (from) parts.push(`From ${from}`);
    else if (to) parts.push(`Up to ${to}`);
  }
  parts.push(`Total in range: ${total}`);
  parts.push(`Today: ${today}`);
  summaryEl.textContent = parts.join(' • ');
  summaryEl.style.display = 'block';
}

function formatNumber(value){
  const num = Number(value);
  if (!Number.isFinite(num)) return '0';
  return num.toLocaleString();
}

document.addEventListener('DOMContentLoaded', async () => {
  initNav();
  initRouter();
  document.querySelectorAll('[data-action="logout"]').forEach(btn => {
    btn.addEventListener('click', logout);
  });
  $('form-register').addEventListener('submit', createMatatu);
  $('btn-edit-search').addEventListener('click', searchMatatu);
  $('btn-list-refresh').addEventListener('click', () => {
    const filterInput = $('list_filter');
    if (filterInput) filterInput.value = '';
    loadMatatus().catch(() => {});
  });
  $('list_filter').addEventListener('input', scheduleListFilter);
  $('btn-tx-load').addEventListener('click', loadTransactions);
  const txMatatu = $('tx_matatu');
  if (txMatatu) txMatatu.addEventListener('change', () => loadTransactions().catch(() => {}));
  const txPlate = $('tx_plate');
  if (txPlate) {
    txPlate.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        loadTransactions().catch(() => {});
      }
    });
  }
  ['tx_from', 'tx_to'].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener('change', () => loadTransactions().catch(() => {}));
  });
  const resetBtn = $('btn-tx-reset');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      if (txMatatu) txMatatu.value = '';
      if (txPlate) txPlate.value = '';
      const fromEl = $('tx_from');
      const toEl = $('tx_to');
      if (fromEl) fromEl.value = '';
      if (toEl) toEl.value = '';
      loadTransactions().catch(() => {});
    });
  }

  const ok = await ensureAuth();
  if(!ok) return;
  await fetchConfig();
  await loadMatatus();
});

