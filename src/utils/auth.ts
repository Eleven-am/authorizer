import { PrismaClient } from '@prisma/client';
import { betterAuth } from 'better-auth';
import { prismaAdapter } from 'better-auth/adapters/prisma';
import {
    admin,
    jwt,
    openAPI,
    username,
    phoneNumber,
} from 'better-auth/plugins';
import { passkey } from 'better-auth/plugins/passkey';

export function auth () {
    return betterAuth({
        appName: '',
        baseURL: '',
        secret: '',
        database: prismaAdapter(new PrismaClient(), {
            provider: 'sqlite',
        }),
        socialProviders: {
            google: {
                clientId: '',
                clientSecret: '',
            },
            github: {
                clientId: '',
                clientSecret: '',
            },
        },
        emailAndPassword: {
            enabled: true,
            requireEmailVerification: true,
            sendResetPassword: async (a, b) => console.log('a', a, 'b', b),
        },
        emailVerification: {
            sendOnSignUp: true,
            autoSignInAfterVerification: true,
            sendVerificationEmail: async (a, b) => console.log('a', a, 'b', b),
        },
        plugins: [
            passkey({
                rpID: '',
                rpName: '',
            }),
            phoneNumber(),
            username(),
            openAPI(),
            admin(),
            jwt(),
        ],
    })
}