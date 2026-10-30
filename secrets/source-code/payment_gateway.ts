// VULNERABLE: Hardcoded Stripe API Secret Key (CWE-798)
export const STRIPE_API_KEY = "sk_test_51Mz8xK4L9vP2wQ7tR1yT3uI5oP7aS9dF1gH3jK5lZ7xC9vB1nM3kL5jH7gF9";

export function chargeCustomer(amount: number) {
    console.log(`Processing charge of $${amount} via Stripe API`);
}
