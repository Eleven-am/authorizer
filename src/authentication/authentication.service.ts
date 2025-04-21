import { createUnauthorizedError, TaskEither } from '@eleven-am/fp';
import { Logger } from '@nestjs/common';
import { betterAuth } from 'better-auth';
import { prismaAdapter } from 'better-auth/adapters/prisma';
import { fromNodeHeaders, toNodeHandler } from 'better-auth/node';
import { admin, openAPI, username } from 'better-auth/plugins';
import { passkey } from 'better-auth/plugins/passkey';
import { Request } from 'express';

import { AuthenticationOptions } from './authentication.contracts';
import { CURRENT_SESSION_KEY, CURRENT_TOKEN_KEY } from './authentication.constants';
import { Context } from '@eleven-am/pondsocket-nest';
import { AuthorizationContext } from "../types";
import {RedisOptions} from "@eleven-am/pondsocket/types";

export class AuthenticationService {
    private readonly authClient: ReturnType<typeof this.buildAuth>;
    private readonly logger = new Logger(AuthenticationService.name);

    constructor(
        private readonly option: AuthenticationOptions,
    ) {
        this.authClient = this.buildAuth();
    }

    getRedisOptions() {
        return this.option.redisOptions as RedisOptions;
    }

    getSession(ctx: AuthorizationContext) {
        return TaskEither.of(ctx)
            .matchTask([
                {
                    predicate: (ctx) => ctx.isSocket,
                    run: () => this.getSessionFromContext(ctx.getSocketContext()),
                },
                {
                    predicate: () => !ctx.isSocket,
                    run: (ctx) => this.getSessionFromRequest(ctx.getRequest()),
                },
            ])
            .mapError(() => createUnauthorizedError('User is not authenticated'))
            .ioSync((session) => ctx.addData(CURRENT_SESSION_KEY, session))
            .ioSync((session) => ctx.addData<string>(CURRENT_TOKEN_KEY, session.session.token))
            .map((session) => session.user);
    }

    allowNoRulesAccess(ctx: AuthorizationContext) {
        return TaskEither
            .of(ctx)
            .filter(
                (context) => context.isHttp,
                () => createUnauthorizedError('User is not authenticated'),
            )
            .map(() => true);
    }

    handler() {
        return toNodeHandler(this.authClient);
    }

    getSessionFromToken(token: string) {
        return TaskEither
            .tryCatch(
                () => this.option.database.client.session.findFirst({
                    where: {
                        AND: [
                            {
                                token: token ?? '',
                            },
                            {
                                expiresAt: {
                                    gte: new Date(),
                                },
                            },
                        ],
                    },
                    include: {
                        user: true,
                    },
                }),
                'Failed to get session',
            )
            .nonNullable('Failed to get session')
            .mapError(() => createUnauthorizedError('User is not authenticated'))
            .map((session) => ({
                user: (session as any).user,
                session: session,
            }));
    }

    private buildAuth() {
        return betterAuth({
            logger: this.logger,
            trustedOrigins: ['http://localhost:5173'],
            appName: this.option.application.name,
            baseURL: this.option.application.address,
            secret: this.option.application.secret,
            database: prismaAdapter(this.option.database.client, {
                provider: this.option.database.provider,
            }),
            socialProviders: {
                google: this.option.google,
                github: this.option.github,
            },
            emailAndPassword: {
                enabled: true,
                requireEmailVerification: true,
                sendResetPassword: ({ user, url, token }) => this.option.notification
                    .sendResetPasswordEmail(user.email, url, token),
            },
            emailVerification: {
                sendOnSignUp: true,
                autoSignInAfterVerification: true,
                sendVerificationEmail: ({ user, url, token }) => this.option.notification
                    .sendVerificationEmail(user.email, url, token),
            },
            plugins: [
                passkey({
                    rpID: this.option.application.rpId,
                    rpName: this.option.application.rpName,
                }),
                username(),
                openAPI(),
                admin(),
            ],
        });
    }

    private getSessionFromContext(ctx: Context<'/:token'>) {
        const token = ctx.event?.params?.token ?? ctx.event?.query?.token ?? ctx.assigns?.token ?? null;

        return TaskEither
            .fromNullable(token)
            .chain((token) => this.getSessionFromToken(token));
    }

    private getSessionFromRequest(req: Request) {
        return TaskEither
            .tryCatch(
                () => this.authClient.api.getSession({
                    headers: fromNodeHeaders(req.headers),
                }) as Promise<any>,
                'Failed to get session',
            )
            .nonNullable('Failed to get session');
    }
}


