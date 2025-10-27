#!/usr/bin/env node
// Seed sample matatus and allocate USSD codes via Supabase RPC
// Usage: node scripts/seed.js --count 10 --start 1 --allocate

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE in environment');
  process.exit(1);
}

const argv = process.argv.slice(2);
function getFlag(name, def) {
  const i = argv.findIndex((a) => a === `--${name}`);
  if (i === -1) return def;
  const v = argv[i + 1];
  if (v == null || v.startsWith('--')) return true;
  return v;
}

const COUNT = Number(getFlag('count', 10));
const START = Number(getFlag('start', 1));
const ALLOCATE = Boolean(getFlag('allocate', false));
const TX_PER = Number(getFlag('tx-per', 0));

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { autoRefreshToken: false, persistSession: false },
});

function plateFor(n) {
  // Simple deterministic plate generator: KXX NNN L
  const prefixes = ['KDA', 'KDB', 'KDC', 'KDD', 'KDE', 'KDF', 'KDG'];
  const suffixes = ['A', 'B', 'C', 'D', 'E'];
  const pref = prefixes[n % prefixes.length];
  const num = String(100 + (n % 900));
  const suf = suffixes[n % suffixes.length];
  return `${pref} ${num}${suf}`.toUpperCase();
}

async function main() {
  console.log(`Seeding ${COUNT} matatus starting at index ${START} (allocate=${ALLOCATE}, tx-per=${TX_PER})`);
  const created = [];
  for (let i = 0; i < COUNT; i++) {
    const idx = START + i;
    const plate = plateFor(idx);
    const payload = {
      plate,
      name: `Matatu ${idx}`,
      sacco_name: `SACCO ${Math.ceil(idx / 10)}`,
      till_number: String(500100 + idx),
    };
    const { data, error } = await supabase
      .from('matatus')
      .upsert(payload, { onConflict: 'plate' })
      .select('*')
      .maybeSingle();
    if (error) throw error;
    created.push(data);
  }
  console.log(`Upserted ${created.length} matatus`);

  if (ALLOCATE) {
    const results = [];
    for (const m of created) {
      const { data: code, error } = await supabase.rpc('assign_ussd_code', { p_matatu_id: m.id });
      if (error) {
        results.push({ id: m.id, plate: m.plate, error: error.message });
      } else {
        results.push({ id: m.id, plate: m.plate, code, dial: `*${process.env.USSD_ROOT || '123'}*${code}#` });
      }
    }
    console.table(results);
  } else {
    console.table(created.map((m) => ({ id: m.id, plate: m.plate })));
  }

  if (TX_PER > 0) {
    await seedTransactions(created, TX_PER);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

async function seedTransactions(matatus, txPerMatatu) {
  if (!matatus.length) {
    console.log('No matatus available for transactions seeding.');
    return;
  }
  const seedId = Date.now();
  let total = 0;
  for (const matatu of matatus) {
    for (let i = 0; i < txPerMatatu; i++) {
      const status = 'success';
      const amount = (Math.floor(Math.random() * 40) + 10) * 10;
      const msisdn = randomMsisdn();
      const createdAt = randomRecentDate(10);
      const { error } = await supabase.from('transactions').insert({
        matatu_id: matatu.id,
        amount,
        msisdn,
        status,
        mpesa_receipt: status === 'success' ? `SEED${seedId}${total}` : null,
        gateway_ref: `SEED-${seedId}-${matatu.id}-${i}`,
        created_at: createdAt.toISOString(),
      });
      if (error) throw error;
      total += 1;
    }
  }
  console.log(`Seeded ${total} transactions across ${matatus.length} matatus`);
}

function randomMsisdn() {
  const prefix = Math.random() > 0.2 ? '2547' : '2541';
  const suffix = Math.floor(1000000 + Math.random() * 9000000).toString();
  return prefix + suffix;
}

function randomRecentDate(withinDays = 7) {
  const now = new Date();
  const offset = Math.floor(Math.random() * withinDays);
  const dt = new Date(now);
  dt.setDate(now.getDate() - offset);
  dt.setHours(Math.floor(Math.random() * 24), Math.floor(Math.random() * 60), Math.floor(Math.random() * 60), 0);
  return dt;
}
