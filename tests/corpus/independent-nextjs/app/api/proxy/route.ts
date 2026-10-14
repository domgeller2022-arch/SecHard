import { NextRequest, NextResponse } from 'next/server';
import axios from 'axios';

export async function GET(request: NextRequest) {
  const target = request.nextUrl.searchParams.get('url')!;
  const upstream = await axios.get(target);
  return NextResponse.json(upstream.data);
}
