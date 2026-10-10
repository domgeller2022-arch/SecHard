// FIXTURE: the fixed counterpart - allowlisted destinations and validated responses.
const ALLOWED_HOSTS = new Set(['widgets.example.invalid']);

export function allowedTarget(raw: string): URL {
  const target = new URL(raw);
  if (!ALLOWED_HOSTS.has(target.hostname)) {
    throw new Error('destination is not allowlisted');
  }
  return target;
}

export interface Widget {
  readonly id: string;
  readonly title: string;
}

function isWidget(value: unknown): value is Widget {
  const candidate = value as { id?: unknown; title?: unknown } | null;
  return candidate !== null && typeof candidate.id === 'string' && typeof candidate.title === 'string';
}

export async function fetchWidget(widgetId: string): Promise<Widget> {
  const target = allowedTarget(`https://widgets.example.invalid/${encodeURIComponent(widgetId)}`);
  const response = await fetch(target);
  if (!response.ok) {
    throw new Error(`widget fetch failed: ${String(response.status)}`);
  }
  const parsed: unknown = await response.json();
  if (!isWidget(parsed)) {
    throw new Error('widget response failed validation');
  }
  return parsed;
}
