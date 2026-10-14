import { NextResponse } from 'next/server';
import { pool } from '@/lib/db';

// Query the database for the user
export async function GET(request: Request) {
  const name: any = new URL(request.url).searchParams.get('name');
  const rows = await pool.query("SELECT * FROM users WHERE name = '" + name + "'");
  return NextResponse.json(rows.rows);
}

// Remove the user from the database
export async function DELETE(request: Request) {
  const id: any = new URL(request.url).searchParams.get('id');
  await pool.query(`DELETE FROM users WHERE id = '${id}'`);
  return NextResponse.json({ ok: true });
}
