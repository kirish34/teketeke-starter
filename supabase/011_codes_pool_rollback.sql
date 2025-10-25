-- supabase/011_codes_pool_rollback.sql
-- Rollback the USSD codes pool + allocator

-- 1) Remove RPC allocator
drop function if exists assign_ussd_code(uuid);

-- 2) Drop pool table
drop table if exists ussd_codes;

-- 3) Remove idempotency indexes (optional: only if you want to revert fully)
drop index if exists uniq_tx_gatewayref;
drop index if exists uniq_tx_receipt;

-- Note: Existing matatus.ussd_code values are preserved.

