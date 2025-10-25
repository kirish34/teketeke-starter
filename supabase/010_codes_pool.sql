-- supabase/010_codes_pool.sql
-- USSD codes pool + transactional allocator + idempotency indexes

-- 1) Pool table (001..999 -> ABCX checksum codes)
create table if not exists ussd_codes (
  base text primary key,                  -- '001'
  code text not null unique,              -- '0011'
  status text not null default 'free' check (status in ('free','assigned')),
  assigned_to uuid references matatus(id),
  assigned_at timestamptz
);

-- 2) Seed pool if empty (or partially) with ABCX codes
insert into ussd_codes(base, code, status)
select base,
       base ||
       case
         when ((substr(base,1,1)::int + substr(base,2,1)::int + substr(base,3,1)::int) % 9) = 0
           then '9'
         else ((substr(base,1,1)::int + substr(base,2,1)::int + substr(base,3,1)::int) % 9)::text
       end,
       'free'
from (
  select lpad(gs::text, 3, '0') as base
  from generate_series(1,999) as gs
) t
on conflict (base) do nothing;

-- 3) If some matatus already have ussd_code, mark those as assigned in the pool
update ussd_codes u
set status = 'assigned', assigned_to = m.id, assigned_at = now()
from matatus m
where m.ussd_code is not null
  and u.code = m.ussd_code
  and u.status <> 'assigned';

-- 4) Idempotency indexes on transactions
create unique index if not exists uniq_tx_receipt
  on transactions (mpesa_receipt)
  where mpesa_receipt is not null;

create unique index if not exists uniq_tx_gatewayref
  on transactions (gateway_ref)
  where gateway_ref is not null;

-- 5) Transactional allocator: picks the next FREE code and assigns it to the matatu
drop function if exists assign_ussd_code(uuid);
create or replace function assign_ussd_code(p_matatu_id uuid)
returns text
language plpgsql
as $$
declare
  v_existing text;
  v_base text;
  v_code text;
begin
  -- If matatu already has a code, return it (idempotent behavior)
  select ussd_code into v_existing from matatus where id = p_matatu_id;
  if v_existing is not null then
    return v_existing;
  end if;

  -- Pick next free code atomically
  select base, code
    into v_base, v_code
  from ussd_codes
  where status = 'free'
  order by base
  for update skip locked
  limit 1;

  if v_code is null then
    raise exception 'No free USSD codes available';
  end if;

  -- Mark as assigned and attach to matatu
  update ussd_codes
     set status = 'assigned', assigned_to = p_matatu_id, assigned_at = now()
   where base = v_base;

  update matatus
     set ussd_code = v_code
   where id = p_matatu_id;

  return v_code;
end;
$$;

