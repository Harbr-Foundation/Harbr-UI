// src/routes/(auth)/auth/+page.server.ts
import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import bcrypt from 'bcrypt';
import { dev } from '$app/environment';
import jwt from 'jsonwebtoken';

// Get JWT secret from environment with fallback for development
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    if (dev) {
        console.warn('WARNING: JWT_SECRET not set in environment variables. Using insecure default for development.');
    } else {
        throw new Error('JWT_SECRET must be set in production environment');
    }
}

// Use a secure default only for development
const jwtSecret = JWT_SECRET || (dev ? 'dev-jwt-secret' : '');

// Redirect if user is already logged in
export const load: PageServerLoad = async ({ locals }) => {
    if (locals.user) {
        throw redirect(302, '/dashboard');
    }
};

// Add rate limiting with proper TypeScript types
interface RateLimitAttempt {
    count: number;
    firstAttempt: number;
}

const loginAttempts = new Map<string, RateLimitAttempt>();

function checkRateLimit(email: string): boolean {
    const now = Date.now();
    const attempt = loginAttempts.get(email);

    if (!attempt) {
        loginAttempts.set(email, { count: 1, firstAttempt: now });
        return true;
    }

    // Reset if it's been more than 15 minutes
    if (now - attempt.firstAttempt > 15 * 60 * 1000) {
        loginAttempts.set(email, { count: 1, firstAttempt: now });
        return true;
    }

    // Allow up to 5 attempts in 15 minutes
    if (attempt.count >= 5) {
        return false;
    }

    attempt.count++;
    return true;
}

export const actions = {
    login: async ({ request, cookies }) => {
        const formData = await request.formData();
        const email = formData.get('email');
        const password = formData.get('password');

        if (
            !email ||
            !password ||
            typeof email !== 'string' ||
            typeof password !== 'string'
        ) {
            return fail(400, { invalid: true });
        }

        // Check rate limiting before processing login
        if (!checkRateLimit(email.toLowerCase())) {
            return fail(429, { rateLimit: true });
        }

        try {
            const user = await db.user.findUnique({
                where: { email: email.toLowerCase() }
            });

            if (!user) {
                // Use a generic error message to prevent user enumeration
                return fail(400, { credentials: true });
            }

            const passwordMatch = await bcrypt.compare(password, user.passwordHash);

            if (!passwordMatch) {
                return fail(400, { credentials: true });
            }

            // Create a JWT token with minimal payload
            const token = jwt.sign(
                { 
                    userId: user.id,
                    email: user.email
                },
                jwtSecret,
                { 
                    expiresIn: '7d',
                    algorithm: 'HS256'
                }
            );

            // Set secure HTTP-only cookie
            cookies.set('session', token, {
                path: '/',
                httpOnly: true,
                secure: !dev,
                sameSite: 'strict',
                maxAge: 60 * 60 * 24 * 7, // 7 days
            });

            throw redirect(302, '/dashboard');
        } catch (error) {
            console.error('Login error:', error);
            return fail(500, { error: true });
        }
    },

    register: async ({ request, cookies }) => {
        const formData = await request.formData();
        const email = formData.get('email');
        const password = formData.get('password');
        const username = formData.get('username');

        if (
            !email ||
            !password ||
            !username ||
            typeof email !== 'string' ||
            typeof password !== 'string' ||
            typeof username !== 'string'
        ) {
            return fail(400, { invalid: true });
        }

        // Enhanced password validation
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{10,}$/;
        if (!passwordRegex.test(password)) {
            return fail(400, { 
                password: 'Password must be at least 10 characters and contain uppercase, lowercase, numbers, and special characters'
            });
        }

        try {
            // Check if user already exists
            const exists = await db.user.findFirst({
                where: { 
                    OR: [
                        { email: email.toLowerCase() },
                        { username }
                    ]
                }
            });

            if (exists) {
                return fail(400, { user: 'exists' });
            }

            // Hash password with appropriate cost factor
            const saltRounds = 12;
            const passwordHash = await bcrypt.hash(password, saltRounds);

            // Create user with email verified false by default
            const user = await db.user.create({
                data: {
                    email: email.toLowerCase(),
                    username,
                    passwordHash,
                    emailVerified: false
                }
            });

            // Create JWT token
            const token = jwt.sign(
                { 
                    userId: user.id,
                    email: user.email
                },
                jwtSecret,
                { 
                    expiresIn: '7d',
                    algorithm: 'HS256'
                }
            );

            // Set secure HTTP-only cookie
            cookies.set('session', token, {
                path: '/',
                httpOnly: true,
                secure: !dev,
                sameSite: 'strict',
                maxAge: 60 * 60 * 24 * 7, // 7 days
            });

            // Send verification email
            await sendVerificationEmail(user.email, user.id);

            throw redirect(302, '/dashboard');
        } catch (error) {
            console.error('Registration error:', error);
            return fail(500, { error: true });
        }
    },

    logout: async ({ cookies }) => {
        cookies.delete('session', { path: '/' });
        throw redirect(302, '/auth');
    }
} satisfies Actions;

async function sendVerificationEmail(email: string, userId: string) {
    try {
        const verificationToken = jwt.sign(
            { userId },
            jwtSecret,
            { expiresIn: '24h' }
        );

        const verificationUrl = new URL('/verify', process.env.PUBLIC_URL || 'http://localhost:5173');
        verificationUrl.searchParams.set('token', verificationToken);

        // Implement your email service here
        // await emailService.send({
        //     to: email,
        //     subject: 'Verify your email',
        //     text: `Click here to verify your email: ${verificationUrl.toString()}`
        // });
    } catch (error) {
        console.error('Error sending verification email:', error);
        // Don't throw - we don't want to prevent registration if email fails
    }
}