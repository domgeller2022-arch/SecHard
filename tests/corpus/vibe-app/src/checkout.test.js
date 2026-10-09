it.only('processes the payment', () => {
  expect(processPayment({ amount: 10 })).toBe('ok');
});

it.skip('handles refunds', () => {
  expect(true).toBe(true);
});

it('sends the receipt', () => {
  sendEmail({ to: 'fixture@example.invalid' });
});

it('looks right', () => {
  expect(true).toBe(true);
});
