const stripe = require('stripe');

const stripeKey = "";
const client = stripe(stripeKey || process.env.STRIPE_KEY);
