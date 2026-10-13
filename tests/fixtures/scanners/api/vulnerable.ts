// FIXTURE: SSRF and unsafe-consumption shapes for the API Top 10 rules. The first two calls use
// request-derived URLs directly; the third routes through a variable first - the shape the
// regex-only rule honestly missed, and the reason Batch F-04 replaced it with the taint rule,
// which follows the value through the assignment. All three are expected findings now.
export interface FixtureRequest {
  readonly url: string;
  readonly params: Readonly<Record<string, string>>;
}

export async function proxy(request: FixtureRequest): Promise<unknown> {
  const response = await fetch(request.url);
  return response.json();
}

export async function renderTemplate(request: FixtureRequest): Promise<unknown> {
  const response = await fetch(String(request.params['templateUrl']));
  return response.json();
}

export async function indirectProxy(request: FixtureRequest): Promise<unknown> {
  const target = String(request.url);
  const response = await fetch(target);
  return response.json();
}
