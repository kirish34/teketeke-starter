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
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || res.statusText);
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
let _transactions = [];
async function loadMatatus(){
  const out = await api('/api/matatus');
  _matatus = out.items || [];
  renderList(_matatus);
}

function filterList(){
  const q = $('list_filter').value.trim().toUpperCase();
  const list = !q ? _matatus : _matatus.filter(x => (x.plate||'').toUpperCase().includes(q));
  renderList(list);
}

function renderList(items){
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = '';
  items.forEach(x=>{
    const tr = document.createElement('tr');

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
  const q = $('edit_search').value.trim().toUpperCase();
  if(!q){ $('edit_result').innerHTML = '<span class="muted">Enter a plate.</span>'; return; }
  const out = await api('/api/matatus');
  const found = (out.items || []).find(x => (x.plate||'').toUpperCase() === q);
  if(!found){ $('edit_result').innerHTML = 'No match.'; return; }
  renderEdit(found);
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
  if (!hint || !table || !tbody) return;

  hint.style.display = 'block';
  hint.textContent = 'Loading transactions...';
  table.style.display = 'none';
  tbody.innerHTML = '';

  const params = new URLSearchParams();
  const plateQuery = ($('tx_plate')?.value || '').trim();
  if (plateQuery) params.set('plate', plateQuery);
  const url = params.toString() ? `/api/transactions?${params.toString()}` : '/api/transactions';

  try {
    const out = await api(url);
    _transactions = out.items || [];
    renderTransactions(_transactions);
  } catch (err) {
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

document.addEventListener('DOMContentLoaded', async () => {
  initNav();
  initRouter();
  document.querySelectorAll('[data-action="logout"]').forEach(btn => {
    btn.addEventListener('click', logout);
  });
  $('form-register').addEventListener('submit', createMatatu);
  $('btn-edit-search').addEventListener('click', searchMatatu);
  $('btn-list-refresh').addEventListener('click', loadMatatus);
  $('list_filter').addEventListener('input', filterList);
  $('btn-tx-load').addEventListener('click', loadTransactions);

  const ok = await ensureAuth();
  if(!ok) return;
  await fetchConfig();
  await loadMatatus();
});

