import { createBadRequestError, createForbiddenError, Either, TaskEither } from '@eleven-am/fp';
import { Inject } from '@nestjs/common';
import {
    generateAuthenticationOptions,
    GenerateAuthenticationOptionsOpts,
    generateRegistrationOptions,
    GenerateRegistrationOptionsOpts,
    verifyAuthenticationResponse,
    VerifyAuthenticationResponseOpts,
    verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { AuthenticatorTransportFuture } from '@simplewebauthn/types';
import { Response } from 'express';
import { Details } from 'express-useragent';


import { WEB_AUTHN_CACHE_KEY, AUTHENTICATION_BACKEND } from './authentication.constants';
import {
    AuthenticationBackendInterface,
    AuthenticationResponseJSONParams,
    OauthProvider,
    oauthStateSchema,
    oauthTokenSchema,
    PassKeyData,
    PassKeyParams,
    profileSchema,
    RegisterParams,
    RegistrationResponseJSONParams,
} from './authentication.contracts';
import { HttpService } from '../http/http.service';

export class AuthenticationService {
    constructor (
        private readonly httpService: HttpService,
        @Inject(AUTHENTICATION_BACKEND) private readonly authBackendService: AuthenticationBackendInterface,
    ) {}

    loginWebAuthn (email: string, hostname: string, response: Response) {
        return this.authBackendService.getPassKeys(email, hostname)
            .mapItems((passKey) => ({
                id: passKey.credentialId,
                type: passKey.publicKey,
                transports: passKey.transports as AuthenticatorTransportFuture[],
            }))
            .map((allowCredentials): GenerateAuthenticationOptionsOpts => ({
                allowCredentials,
                userVerification: 'preferred',
                rpID: hostname,
                timeout: 60000,
            }))
            .chain((opts) => TaskEither
                .tryCatch(
                    () => generateAuthenticationOptions(opts),
                    'Error generating registration options',
                ))
            .ioSync((options) => {
                response.cookie(
                    WEB_AUTHN_CACHE_KEY,
                    Buffer.from(JSON.stringify({
                        challenge: options.challenge,
                        email,
                    })).toString('base64'),
                    {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: 'strict',
                        maxAge: 60 * 1000,
                        path: '/',
                    },
                );
            });
    }

    registerWebAuthn (email: string, hostname: string, response: Response) {
        return this.authBackendService.getPassKeys(email, hostname)
            .orElse(() => TaskEither.of([]))
            .mapItems((passKey) => ({
                id: passKey.credentialId,
                type: passKey.publicKey,
                transports: passKey.transports as AuthenticatorTransportFuture[],
            }))
            .map((excludeCredentials) => {
                const opts: GenerateRegistrationOptionsOpts = {
                    rpName: this.authBackendService.rpName(),
                    rpID: hostname,
                    userName: email,
                    timeout: 60000,
                    attestationType: 'none',
                    excludeCredentials,
                    supportedAlgorithmIDs: [-7, -257, -8],
                    authenticatorSelection: {
                        residentKey: 'discouraged',
                        userVerification: 'preferred',
                    },
                    extensions: {
                        appid: hostname,
                    },
                };

                return opts;
            })
            .chain((opts) => TaskEither
                .tryCatch(
                    () => generateRegistrationOptions(opts),
                    'Error generating registration options',
                ))
            .ioSync((options) => {
                response.cookie(
                    WEB_AUTHN_CACHE_KEY,
                    Buffer.from(JSON.stringify({
                        challenge: options.challenge,
                        email,
                    })).toString('base64'),
                    {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: 'strict',
                        maxAge: 60 * 1000,
                        path: '/',
                    },
                );
            });
    }

    loginWebAuthnConfirm (
        passKeyData: PassKeyData,
        body: AuthenticationResponseJSONParams,
        serverAddress: string, hostname: string,
    ) {
        return this.authBackendService.getPassKey(passKeyData.email, hostname, body.id)
            .map((passKey): VerifyAuthenticationResponseOpts => ({
                response: body,
                expectedRPID: hostname,
                expectedOrigin: serverAddress,
                requireUserVerification: false,
                expectedChallenge: passKeyData.challenge,
                credential: {
                    counter: passKey.counter,
                    id: passKey.credentialId,
                    publicKey: this.base64ToUint8Array(passKey.publicKey),
                    transports: passKey.transports as AuthenticatorTransportFuture[],
                },
            }))
            .chain((opts) => TaskEither
                .tryCatch(
                    () => verifyAuthenticationResponse(opts),
                    'Error verifying authentication response',
                ))
            .filter(
                (response) => response.verified,
                () => createBadRequestError('WebAuthn login failed'),
            )
            .chain(({ authenticationInfo }) => this.authBackendService
                .updatePassKey(passKeyData.email, hostname, authenticationInfo.credentialID, authenticationInfo.newCounter))
            .chain(() => this.authBackendService.getUserByEmail(passKeyData.email));
    }

    registerWebAuthnConfirm (
        params: PassKeyParams,
        passKeyData: PassKeyData,
        body: RegistrationResponseJSONParams,
        serverAddress: string, hostname: string,
    ) {
        return TaskEither
            .of({
                email: params.email,
                username: params.username,
            })
            .chain((params) => this.verifyRegisterParams(params))
            .chain((params) => this.verifyPasskey(body, passKeyData, serverAddress, hostname).map(() => params))
            .chain((params) => this.authBackendService.createUser(params.email, params.username));
    }

    createFirstPassKey (
        passKeyData: PassKeyData,
        body: RegistrationResponseJSONParams,
        serverAddress: string, hostname: string,
    ) {
        return this.authBackendService.getUserByEmail(passKeyData.email)
            .chain((user) => this.verifyPasskey(body, passKeyData, serverAddress, hostname)
                .map(() => user));
    }

    generateURL (oauthId: string, ip: string, details: Details, redirect_uri: string) {
        const state = Buffer.from(JSON.stringify({
            ip,
            details,
        })).toString('base64');

        const buildURL = (oauthClient: OauthProvider) => {
            const params = new URLSearchParams({
                scope: oauthClient.scopes.join(' '),
                client_id: oauthClient.clientId,
                response_type: 'code',
                redirect_uri,
                state,
            });

            const url = `${oauthClient.authorizeUrl}?${params.toString()}`;

            return { url };
        };

        return this.authBackendService.getOauthProvider(oauthId)
            .map(buildURL);
    }

    getOauthData (oauthId: string, code: string, state: string, redirect_uri: string) {
        const creatUser = (email: string, username: string) => this.authBackendService.doesUserExist(email)
            .matchTask([
                {
                    predicate: (exists) => exists,
                    run: () => this.authBackendService.getUserByEmail(email),
                },
                {
                    predicate: () => true,
                    run: () => this.authBackendService.createUser(email, username),
                },
            ]);

        const parsedState = (email: string, username: string) => Either
            .of(Buffer.from(state, 'base64').toString('utf-8'))
            .map(JSON.parse)
            .parseSchema(oauthStateSchema)
            .map(({ ip, details }) => ({
                email,
                username,
                ip,
                details,
            }))
            .toTaskEither()
            .chain(({ email, username, ip, details }) => creatUser(email, username)
                .map((user) => ({
                    user,
                    ip,
                    details,
                })));

        return this.authBackendService.getOauthProvider(oauthId)
            .map((provider) => {
                const params = new URLSearchParams({
                    client_id: provider.clientId,
                    client_secret: provider.clientSecret,
                    grant_type: 'authorization_code',
                    redirect_uri,
                    state,
                    code,
                });

                return {
                    userDataUrl: provider.userDataUrl,
                    url: provider.tokenUrl,
                    params,
                };
            })
            .chain(({ url, userDataUrl, params }) => this.httpService
                .postSafe(
                    url,
                    oauthTokenSchema,
                    params,
                    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
                )
                .map((response) => response.access_token)
                .chain((accessToken) => this.httpService
                    .getSafe(
                        userDataUrl,
                        profileSchema,
                        {
                            headers: {
                                'Content-Type': 'application/json',
                                Authorization: `Bearer ${accessToken}`,
                            },
                        },
                    ))
                .map((response) => {
                    const email = 'email' in response ? response.email : response.mail;
                    const username = email.split('@')[0];

                    return {
                        email,
                        username,
                    };
                }))
            .chain((data) => parsedState(data.email, data.username));
    }

    private Uint8ArrayToBase64 (arr: Uint8Array): string {
        return btoa(String.fromCharCode(...arr));
    }

    private base64ToUint8Array (base64: string): Uint8Array {
        return new Uint8Array(atob(base64).split('')
            .map((char) => char.charCodeAt(0)));
    }

    private verifyRegisterParams (params: RegisterParams) {
        return this.authBackendService.getUserByEmail(params.email)
            .flip(
                () => params,
                () => createForbiddenError('Email already exists'),
            )
            .chain((params) => this.authBackendService.getUserByUsername(params.username))
            .flip(
                () => params,
                () => createForbiddenError('Username already exists'),
            );
    }

    private verifyPasskey (body: RegistrationResponseJSONParams, passKeyData: PassKeyData, serverAddress: string, hostname: string) {
        const opts = {
            response: body,
            expectedChallenge: passKeyData.challenge,
            expectedOrigin: serverAddress,
            expectedRPID: hostname,
            requireUserVerification: false,
        };

        return TaskEither
            .tryCatch(
                () => verifyRegistrationResponse(opts),
                'Error verifying registration response',
            )
            .filter(
                (response) => response.verified && Boolean(response.registrationInfo),
                () => createBadRequestError('WebAuthn registration failed'),
            )
            .chain((response) => this.authBackendService.createPassKey(passKeyData.email, hostname, {
                transports: body.response.transports || [],
                counter: response.registrationInfo!.credential.counter,
                credentialId: response.registrationInfo!.credential.id,
                backedUp: response.registrationInfo!.credentialBackedUp,
                deviceType: response.registrationInfo!.credentialDeviceType,
                publicKey: this.Uint8ArrayToBase64(response.registrationInfo!.credential.publicKey),
            }));
    }
}
