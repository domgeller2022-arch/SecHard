import Link from 'next/link';
import { createClient } from '@/lib/supabase/server';
import { signOut } from '../actions';
import { createNote, deleteNote, updateNote } from './actions';

/**
 * The private page.
 *
 * The query has no `owner_id` filter. That is deliberate: the row-level security policy decides what
 * this user can see, and the page cannot disagree with the policy. If the policy were wrong, this
 * page would show the wrong rows — which is why the authorization tests exercise the boundary
 * directly rather than through the interface.
 */
export default async function Notes() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (user === null) {
    return (
      <main>
        <p>Not signed in. <Link href="/">Sign in</Link>.</p>
      </main>
    );
  }

  const { data: notes, error } = await supabase
    .from('notes')
    .select('id, title, body, updated_at')
    .order('created_at', { ascending: true });

  return (
    <main>
      <p>
        Signed in as {user.email}.{' '}
        <form action={signOut} style={{ display: 'inline' }}>
          <button type="submit">Sign out</button>
        </form>
      </p>

      {error === null ? null : <p role="alert">Could not load notes: {error.message}</p>}

      <h2 style={{ fontSize: '1rem' }}>Your notes</h2>
      <ul data-testid="notes">
        {(notes ?? []).map((note) => (
          <li key={note.id} data-testid="note">
            <strong data-testid="note-title">{note.title}</strong>
            {note.body.length === 0 ? null : <p>{note.body}</p>}
            <form action={updateNote} style={{ display: 'inline' }}>
              <input type="hidden" name="id" value={note.id} />
              <input name="title" defaultValue={note.title} aria-label="New title" />
              <button type="submit">Rename</button>
            </form>
            <form action={deleteNote} style={{ display: 'inline' }}>
              <input type="hidden" name="id" value={note.id} />
              <button type="submit">Delete</button>
            </form>
          </li>
        ))}
      </ul>

      <h2 style={{ fontSize: '1rem' }}>Add a note</h2>
      <form action={createNote}>
        <p>
          <label htmlFor="title">Title</label>
          <br />
          <input id="title" name="title" required maxLength={200} />
        </p>
        <p>
          <label htmlFor="body">Body</label>
          <br />
          <textarea id="body" name="body" maxLength={20000} />
        </p>
        <button type="submit">Save</button>
      </form>
    </main>
  );
}
