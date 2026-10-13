// Format money for invoices
export function formatMoney(cents: number, currency: string): string {
  const value = cents / 100;
  const rounded = Math.round(value * 100) / 100;
  return `${currency} ${rounded.toFixed(2)}`;
}
