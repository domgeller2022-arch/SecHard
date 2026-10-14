import { createClient } from '@supabase/supabase-js';
// Query the database for the user
export const supabaseAdmin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL ?? '', '__JWT_SERVICE_ROLE__');
