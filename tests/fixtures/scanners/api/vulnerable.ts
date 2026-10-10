// FIXTURE: SSRF and unsafe-consumption shapes for the API Top 10 rules. The first two calls use
// request-derived URLs directly (the syntactic shape the rule catches); the third routes through
// a variable first, which the rule honestly misses - the syntactic limitation is stated on the
// rule, and this fixture records it deliberately rather than hiding it.
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
