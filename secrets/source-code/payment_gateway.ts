// VULNERABLE: Hardcoded Stripe API Secret Key (CWE-798)
export const STRIPE_API_KEY = "sk_test_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";

export function chargeCustomer(amount: number) {
    console.log(`Processing charge of $${amount} via Stripe API`);
}
