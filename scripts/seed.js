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
  console.log(`Seeding ${COUNT} matatus starting at index ${START} (allocate=${ALLOCATE})`);
  const created = [];
  for (let i = 0; i < COUNT; i++) {
    const idx = START + i;
    const plate = plateFor(idx);
    const payload = {
      plate,
      name: `Matatu ${idx}`,
      sacco_name: `SACCO ${Math.ceil(idx / 10)}`,
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
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

