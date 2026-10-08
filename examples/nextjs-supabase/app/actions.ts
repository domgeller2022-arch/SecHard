'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { createClient } from '@/lib/supabase/server';

/**
 * Authentication actions.
 *
 * Errors are returned as values, not thrown, so the page can show the user what happened. The
 * messages are deliberately uninformative about which part failed: telling an attacker whether an
 * address exists is a small leak that costs nothing to avoid.
 */

export async function signIn(formData: FormData): Promise<void> {
  const email = String(formData.get('email') ?? '');
  const password = String(formData.get('password') ?? '');

  const supabase = await createClient();
  const { error } = await supabase.auth.signInWithPassword({ email, password });

  if (error !== null) {
    redirect(`/?error=${encodeURIComponent('Sign-in failed. Check your email and password.')}`);
  }

  revalidatePath('/', 'layout');
  redirect('/notes');
}

export async function signOut(): Promise<void> {
  const supabase = await createClient();
  await supabase.auth.signOut();
  revalidatePath('/', 'layout');
  redirect('/');
}
