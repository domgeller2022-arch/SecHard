// FIXTURE: the import shape audit detection reads (Supabase client, Stripe SDK).
import { createClient } from '@supabase/supabase-js';
import Stripe from 'stripe';

export const supabase = createClient('https://fixture.example.invalid', 'sb_publishable_fixture');
export const stripe = new Stripe('sk_test_fixture');
