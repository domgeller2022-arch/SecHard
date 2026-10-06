/** Extracts a semantic version from tool output. */
export function extractVersion(text: string): string | undefined {
  const match = text.match(/\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?/);
  return match?.[0];
}
