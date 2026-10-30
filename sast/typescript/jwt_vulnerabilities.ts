import * as jwt from 'jsonwebtoken';

interface UserPayload {
    userId: string;
    role: string;
}

export function verifyUserToken(token: string, secretKey: string): UserPayload | null {
    try {
        // VULNERABLE: Allowing 'none' algorithm or missing algorithm verification (CWE-347)
        const decoded = jwt.verify(token, secretKey, {
            algorithms: ['HS256', 'none']
        }) as UserPayload;
        return decoded;
    } catch (e) {
        return null;
    }
}
