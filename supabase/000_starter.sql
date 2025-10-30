-- supabase/000_starter.sql
-- Clean minimal schema for Matatus + Tills + USSD + Transactions

create extension if not exists pgcrypto;

create table if not exists matatus (
  id uuid primary key default gen_random_uuid(),
  plate text not null unique,
  name text,
  sacco_name text,
  till_number text unique,
  ussd_code text unique,
  created_at timestamptz default now()
);

create table if not exists transactions (
  id uuid primary key default gen_random_uuid(),
  matatu_id uuid not null references matatus(id) on delete cascade,
  amount numeric(12,2) not null check (amount >= 0),
  msisdn text,
  status text not null check (status in ('pending','success','failed','timeout')),
  mpesa_receipt text,
  gateway_ref text,
  raw jsonb,
  created_at timestamptz default now()
);

create index if not exists idx_tx_matatu_status on transactions(matatu_id, status);
create index if not exists idx_tx_matatu_created on transactions(matatu_id, created_at desc);
create unique index if not exists uniq_tx_gatewayref on transactions(gateway_ref) where gateway_ref is not null;
create unique index if not exists uniq_tx_receipt on transactions(mpesa_receipt) where mpesa_receipt is not null;

create or replace view v_matatu_stats as
select
  m.id as matatu_id,
  m.plate,
  m.name,
  m.sacco_name,
  m.till_number,
  m.ussd_code,
  coalesce(sum(case when t.status = 'success' then 1 else 0 end),0)::int as total_success,
  coalesce(sum(case when t.status = 'failed' then 1 else 0 end),0)::int as total_failed,
  max(t.created_at) as last_tx_at
from matatus m
left join transactions t on t.matatu_id = m.id
group by m.id, m.plate, m.name, m.sacco_name, m.till_number, m.ussd_code;
