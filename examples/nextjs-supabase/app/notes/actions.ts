'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { createClient } from '@/lib/supabase/server';

/**
 * Note actions.
 *
 * Authorization here is deliberately thin, because the boundary is the database. The client acts as
 * the signed-in user, `owner_id` defaults to that user, and the row-level security policy's
 * `WITH CHECK` rejects a row claiming a different owner. A client-supplied `owner_id` is therefore
 * ignored by the schema rather than trusted by this code.
 *
 * The one check the server does make is that somebody is signed in at all, so the user gets a clear
 * message instead of an empty result.
 *
 * Every write inspects its error value and surfaces it: a discarded error is a data-loss path that
 * looks identical to a success (QUAL-07, applied to this application by Batch Q after the
 * external audit's M8 finding).
 */

function failure(message: string, cause: unknown): never {
  // The cause is logged server-side only; the user-facing message carries no internal detail.
  console.error(`notes action failed: ${String(cause)}`);
  redirect(`/notes?error=${encodeURIComponent(message)}`);
}

export async function createNote(formData: FormData): Promise<void> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (user === null) redirect('/');

  const title = String(formData.get('title') ?? '').trim();
  const body = String(formData.get('body') ?? '');
  if (title.length === 0) return;

  const { error } = await supabase.from('notes').insert({ title, body });
  if (error !== null) failure('Could not save the note.', error.message);
  revalidatePath('/notes');
}

export async function updateNote(formData: FormData): Promise<void> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (user === null) redirect('/');

  const id = String(formData.get('id') ?? '');
  const title = String(formData.get('title') ?? '').trim();
  const body = String(formData.get('body') ?? '');
  if (id.length === 0 || title.length === 0) return;

  // No owner filter is added here on purpose: the policy applies it. Adding one would be a second,
  // weaker check that could drift from the policy and give a false sense of protection. The body
  // is part of the update: dropping it silently reverted edits (the audit's M8 finding).
  const { error } = await supabase.from('notes').update({ title, body, updated_at: new Date().toISOString() }).eq('id', id);
  if (error !== null) failure('Could not update the note.', error.message);
  revalidatePath('/notes');
}

export async function deleteNote(formData: FormData): Promise<void> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (user === null) redirect('/');

  const id = String(formData.get('id') ?? '');
  if (id.length === 0) return;

  const { error } = await supabase.from('notes').delete().eq('id', id);
  if (error !== null) failure('Could not delete the note.', error.message);
  revalidatePath('/notes');
}
