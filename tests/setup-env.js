process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.HEALTHCHECK_SKIP_DB = process.env.HEALTHCHECK_SKIP_DB || 'true';
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE || 'test-service-role';
process.env.CALLBACK_SECRET = process.env.CALLBACK_SECRET || 'test-secret';
process.env.ADMIN_USER = process.env.ADMIN_USER || 'admin@example.com';
process.env.ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'super-secret';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'session-secret';
process.env.OPS_WEBHOOK_URL = '';

