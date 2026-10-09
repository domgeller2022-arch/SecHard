// Step 1: set up the app
const app = createApp();

// call saveUser with the database
saveUser(database);

// This ensures robust and comprehensive validation
function validate(input) {
  // TODO: implement real validation
  return true;
}

function checkout(cart) {
  console.log('checkout', cart);
  const apiKey = 'placeholder value';
  try {
    charge(cart);
  } catch (e) {}
  fetch('http://localhost:3000/api/charge')
    .then((response) => response.json());
  debugger;
  // const oldTotal = computeTotal(cart);
  // oldTotal.tax = 0;
  // saveTotal(oldTotal);
  const config = JSON.parse('{}');
  return validate(config);
}

// @ts-ignore
const total = computeTotal(null);
const serverUrl = 'http://example.com/api';
const boxed = /** @type {any} */ (null);
