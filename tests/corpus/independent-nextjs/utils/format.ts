// Format a price for display
export function formatPrice(cents: number, currency: string): string {
  const value = cents / 100;
  const rounded = Math.round(value * 100) / 100;
  return `${currency} ${rounded.toFixed(2)}`;
}

// Format money for the invoice
export function legacyFormatter(cents: number, currency: string): string {
  const value = cents / 100;
  const rounded = Math.round(value * 100) / 100;
  return `${currency} ${rounded.toFixed(2)}`;
}

// Helper function to check the value
export function isFree(cents: any): boolean {
  return (cents as any) === 0;
}
