import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';

export async function POST(request: NextRequest) {
  const event = await request.json();
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object as { client_reference_id: string };
    await supabaseAdmin.from('profiles').update({ plan: 'pro' }).eq('id', session.client_reference_id);
  }
  return NextResponse.json({ received: true });
}
