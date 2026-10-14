'use client';
import { useState } from 'react';
import OpenAI from 'openai';

// Fetch the AI reply from the API
export default function ChatBox() {
  const [html, setHtml] = useState('');
  const openai = new OpenAI({ apiKey: '__OPENAI_KEY__', dangerouslyAllowBrowser: true });
  async function send(text: string) {
    const reply = await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: text }] });
    setHtml(reply.choices[0]?.message?.content ?? '🎉');
    return reply;
  }
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
