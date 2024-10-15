import { PureAbility, AbilityBuilder } from '@casl/ability';
import { Subjects, PrismaQuery } from '@casl/prisma';
import { TaskEither } from '@eleven-am/fp';
import { Context } from '@eleven-am/pondsocket-nest';
import { ExecutionContext, DynamicModule, ModuleMetadata } from '@nestjs/common';
import { AxiosRequestConfig } from 'axios';
import { Response } from 'express';
import { Details } from 'express-useragent';
import { ZodType } from 'zod';

export interface PassKey {
    credentialId: string;
    publicKey: string;
    transports: string[];
    counter: number;
    backedUp: boolean;
    deviceType: 'singleDevice' | 'multiDevice';
}

export interface PassKeyData {
    challenge: string;
    details: Details;
    email: string;
    ip: string;
}

export interface OauthProvider {
    scopes: string[];
    clientId: string;
    clientSecret: string;
    tokenUrl: string;
    authorizeUrl: string;
    userDataUrl: string;
}

export declare enum Action {
    Create = 'create',
    Read = 'read',
    Update = 'update',
    Delete = 'delete',
    Manage = 'manage'
}

export interface SubjectTypes {}

export interface User {}

export interface AuthKey {}

export declare class PassKeyParams {}

export declare class RegistrationResponseJSONParams {}

export declare class AuthenticationResponseJSONParams {}

export declare class PublicKeyCredentialCreationOptionsJSONParams {}

export declare class PublicKeyCredentialRequestOptionsJSONParams {}

type AppSubject = Subjects<SubjectTypes>;

type KeyOfSubject<subject extends AppSubject> = subject extends keyof SubjectTypes ? keyof SubjectTypes[subject] : subject;

export type AppAbilityType = PureAbility<[Action, AppSubject], PrismaQuery>;

export type RuleBuilder = Pick<AbilityBuilder<AppAbilityType>, 'can' | 'cannot'>;

export type ContextMapper<T> = (data: void, context: Request & Record<string, any> | Context) => T;

export interface AsyncMetadata extends ModuleMetadata {
    inject?: any[];
    useFactory: (...args: any[]) => Promise<AuthenticationBackendInterface> | AuthenticationBackendInterface;
}

export interface WillAuthorize {

    /**
     * Define the rules for the given user
     * @param user The user to define the rules for
     * @param builder The ability builder to define the rules with
     */
    forUser(user: User, builder: RuleBuilder): void;

    /**
     * Check if the user is allowed to perform the given http action
     * @param ability The ability to check the action with
     * @param rules The rules to check against
     * @param context The context of the request
     */
    checkHttpAction?(ability: AppAbilityType, rules: Permission[], context: ExecutionContext): TaskEither<boolean>;

    /**
     * Check if the user is allowed to perform the given socket action
     * @param ability The ability to check the action with
     * @param rules The rules to check against
     * @param context The context of the request
     */
    checkSocketAction?(ability: AppAbilityType, rules: Permission[], context: Context): TaskEither<boolean>;
}

export interface Permission<Resource extends AppSubject = AppSubject> {
    action: Action;
    resource: Resource;
    field?: KeyOfSubject<Resource>;
}

export declare class HttpExceptionSchema {
    statusCode: number;

    message: string;

    error: string;
}

/**
 * Decorator to retrieve the current user's ability for the current http request
 */
export declare const CurrentAbility: {
    WS: () => ParameterDecorator;
    HTTP: () => ParameterDecorator;
};

export function createParamDecorator<T>(model: string, mapper: ContextMapper<T>): {
    WS: () => ParameterDecorator;
    HTTP: () => ParameterDecorator;
};

/**
 * Decorator to check if the user can perform the given permissions
 * @param permissions The permissions to check
 */
export declare function CanPerform<Resource extends AppSubject>(...permissions: Permission<Resource>[]): <TFunction extends Function, Y>(target: TFunction | object, propertyKey?: string | symbol, descriptor?: TypedPropertyDescriptor<Y>) => void;

/**
 * Decorator to describe a class as an authorizer for the application
 */
export declare function Authorizer(): <TFunction extends Function, Y>(target: TFunction | object, propertyKey?: string | symbol, descriptor?: TypedPropertyDescriptor<Y>) => void;

/**
 * Sort the given actions by their priority
 * @param actions The actions to sort
 */
export declare function sortActions(actions: Action[]): Action[];

/**
 * A decorator to get the user agent from the request
 */
export declare function UserAgent(): ParameterDecorator;

/**
 * A decorator to get the server address from the request
 */
export declare function ServerAddress(): ParameterDecorator;

/**
 * A decorator to get the host address from the request
 */
export declare function HostAddress(): ParameterDecorator;

/**
 * A decorator to get the passkey session from the request
 */
export declare function PassKeySession(): ParameterDecorator;

export interface AuthenticationBackendInterface {

    /**
     * Get the name of the rp for the webauthn
     */
    rpName(): string;

    /**
     * Create a new user with the given email and username
     * @param email The email of the user
     * @param username The username of the user
     */
    createUser(email: string, username: string): TaskEither<User>;

    /**
     * Get a user by their username
     * @param username The username of the user
     */
    getUserByUsername(username: string): TaskEither<User>;

    /**
     * Get a user by their email
     * @param email The email of the user
     */
    getUserByEmail(email: string): TaskEither<User>;

    /**
     * Get a user by their id
     * @param userId The id of the user
     */
    getUserById(userId: string): TaskEither<User>;

    /**
     * Check if the user exists with the given email
     * @param email The email of the user
     */
    doesUserExist(email: string): TaskEither<boolean>;

    /**
     * Update the given user
     * @param user The user to update
     */
    updateUser(user: User): TaskEither<User>;

    /**
     * Delete the given user
     * @param user The user to delete
     */
    deleteUser(user: User): TaskEither<User>;

    /**
     * Get an auth key by its key
     * @param authKey The key of the auth key
     */
    getAuthKey(authKey: string): TaskEither<AuthKey>;

    /**
     * Revoke the given auth key
     * @param authKey The key of the auth key
     * @param user The user to revoke the auth key for
     */
    revokeAuthKey(authKey: string, user: User): TaskEither<AuthKey>;

    /**
     * Get the passkeys for the given email and hostname
     * @param email The email of the user
     * @param hostname The hostname of the device
     */
    getPassKeys(email: string, hostname: string): TaskEither<PassKey[]>;

    /**
     * Get the passkey for the given email, hostname and credential id
     * @param email The email of the user
     * @param hostname The hostname of the device
     * @param credentialId The id of the credential
     */
    getPassKey(email: string, hostname: string, credentialId: string): TaskEither<PassKey>;

    /**
     * Create a new passkey for the given email, hostname and passkey
     * @param email The email of the user
     * @param hostname The hostname of the device
     * @param passKey The passkey to create
     */
    createPassKey(email: string, hostname: string, passKey: PassKey): TaskEither<unknown>;

    /**
     * Update the passkey for the given email, hostname and counter
     * @param email The email of the user
     * @param hostname The hostname of the device
     * @param credentialId The id of the credential
     * @param counter The counter of the passkey
     */
    updatePassKey(email: string, hostname: string, credentialId: string, counter: number): TaskEither<PassKey>;

    /**
     * Get the oauth provider by its id
     * @param oauthId The id of the oauth provider
     */
    getOauthProvider(oauthId: string): TaskEither<OauthProvider>;
}

export declare class AuthenticationModule {
    static forRoot (moduleOptions: AsyncMetadata): DynamicModule;
}

export declare class AuthenticationService {
    /**
     * Login with webauthn
     * @param email The email of the user
     * @param hostname The hostname of the device
     * @param response The response from the device
     */
    loginWebAuthn(email: string, hostname: string, response: Response): TaskEither<PublicKeyCredentialRequestOptionsJSONParams>;

    /**
     * Register with webauthn
     * @param email The email of the user
     * @param hostname The hostname of the device
     * @param response The response from the device
     */
    registerWebAuthn(email: string, hostname: string, response: Response): TaskEither<PublicKeyCredentialCreationOptionsJSONParams>;

    /**
     * Create the first passkey
     * @param passKeyData The passkey data
     * @param body The response from the device
     * @param serverAddress The address of the server
     * @param hostname The hostname of the device
     */
    createFirstPassKey(passKeyData: PassKeyData, body: RegistrationResponseJSONParams, serverAddress: string, hostname: string): TaskEither<User>;

    /**
     * Confirm the login with webauthn
     * @param passKeyData The passkey data
     * @param body The response from the device
     * @param serverAddress The address of the server
     * @param hostname The hostname of the device
     */
    loginWebAuthnConfirm(passKeyData: PassKeyData, body: AuthenticationResponseJSONParams, serverAddress: string, hostname: string): TaskEither<User>;

    /**
     * Confirm the registration with webauthn
     * @param params The passkey params
     * @param passKeyData The passkey data
     * @param body The response from the device
     * @param serverAddress The address of the server
     * @param hostname The hostname of the device
     */
    registerWebAuthnConfirm(params: PassKeyParams, passKeyData: PassKeyData, body: RegistrationResponseJSONParams, serverAddress: string, hostname: string): TaskEither<User>;

    /**
     * Generate the url for the given oauth id, ip, details and redirect uri
     * @param oauthId The id of the oauth provider
     * @param ip The ip of the user
     * @param authKey The auth key of the user
     * @param details The details of the user
     * @param redirect_uri The redirect uri
     */
    generateURL(oauthId: string, ip: string, authKey: string, details: Details, redirect_uri: string): TaskEither<{
        url: string;
    }>;

    /**
     * Get the oauth data for the given oauth id, code, state and redirect uri
     * @param oauthId The id of the oauth provider
     * @param code The code of the oauth provider
     * @param state The state of the oauth provider
     * @param redirect_uri The redirect uri
     */
    getOauthData(oauthId: string, code: string, state: string, redirect_uri: string): TaskEither<{
        user: User;
        ip: string;
        details: Details;
    }>;
}

export declare class HttpModule {}

export declare class HttpService {
    /**
     * Get the data from the given url and validate it with the given schema
     * @param url The url to get the data from
     * @param schema The schema to validate the data with
     * @param options The options for the request
     */
    getSafe<DataType>(url: string, schema: ZodType<DataType>, options?: AxiosRequestConfig): TaskEither<DataType>;

    /**
     * Post the data to the given url and validate the response with the given schema
     * @param url The url to post the data to
     * @param schema The schema to validate the response with
     * @param data The data to post
     * @param options The options for the request
     */
    postSafe<DataType>(url: string, schema: ZodType<DataType>, data: unknown, options?: AxiosRequestConfig): TaskEither<DataType>;

    /**
     * Get the data from the given url
     * @param url The url to get the data from
     * @param options The options for the request
     */
    apiGet<T>(url: string, options?: AxiosRequestConfig): TaskEither<T>;
}

export declare class AuthorizationModule {}

export declare class AuthorizationService {
    /**
     * Check if the user is allowed to perform the given http action, to be used in a guard
     * @param user The user to check the action for
     * @param context The context of the request
     */
    checkHttpAction(user: User | null, context: ExecutionContext): TaskEither<boolean>;

    /**
     * Check if the user is allowed to perform the given socket action, to be used in a guard
     * @param user The user to check the action for
     * @param context The context of the request
     */
    checkSocketAction(user: User | null, context: Context): TaskEither<boolean>;
}
