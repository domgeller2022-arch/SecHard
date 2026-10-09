it('processes the payment', () => {
  expect(processPayment({ amount: 10 })).toEqual({ status: 'charged' });
});

it('rejects an empty cart', () => {
  expect(() => checkout([])).toThrow('validation failed');
});

it('computes the total', () => {
  expect(computeTotal([{ price: 2 }, { price: 3 }])).toBe(5);
});
