import { PureAbility, AbilityBuilder } from '@casl/ability';
import { Subjects, PrismaQuery } from '@casl/prisma';
import { TaskEither } from '@eleven-am/fp';
import { Context, CanActivate as CanActivateSocket } from '@eleven-am/pondsocket-nest';
import type { PondEventMap, PondPresence, PondAssigns } from '@eleven-am/pondsocket/types';
import { ExecutionContext, DynamicModule, ModuleMetadata, LoggerService, CanActivate, Type } from '@nestjs/common';
import { Response, Request } from 'express';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Session } from "better-auth";
import { PrismaClient } from "@prisma/client";
import { RedisOptions } from '@eleven-am/pondsocket/types';

interface OAUTH2Config {
    clientId: string;
    clientSecret: string;
}

interface ApplicationConfig {
    name: string;
    secret: string;
    version: string;
    address: string;
    description: string;
    rpId: string;
    rpName: string;
}

interface PrismaAdapter {
    provider: "sqlite" | "cockroachdb" | "mysql" | "postgresql" | "sqlserver" | "mongodb";
    client: PrismaClient;
}

export interface AuthenticationOptions {
    google?: OAUTH2Config;
    github?: OAUTH2Config;
    application: ApplicationConfig;
    notification: NotificationService;
    database: PrismaAdapter;
    redisOptions?: RedisOptions;
}


export declare enum Action {
    Create = 'create',
    Read = 'read',
    Update = 'update',
    Delete = 'delete',
    Manage = 'manage'
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface SubjectTypes {}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface User {}

export interface CachedSession {
    user: User;
    session: Session
}

type AppSubject = Subjects<SubjectTypes>;

type KeyOfSubject<subject extends AppSubject> = subject extends keyof SubjectTypes ? keyof SubjectTypes[subject] : subject;

export type AppAbilityType = PureAbility<[Action, AppSubject], PrismaQuery>;

export type RuleBuilder = Pick<AbilityBuilder<AppAbilityType>, 'can' | 'cannot'>;

export type ContextMapper<T> = (context: AuthorizationContext) => T;

export interface WillAuthorize {

    /**
     * Define the rules for the given user
     * @param user The user to define the rules for
     * @param builder The ability builder to define the rules with
     */
    forUser(user: User, builder: RuleBuilder): void;

    /**
     * Check if the user is allowed to perform the given action on the given resource
     * @param context The context of the request
     * @param ability The ability to check the action with
     * @param rules The rules to check against
     */
    authorize?(context: AuthorizationContext, ability: AppAbilityType, rules: Permission[]): TaskEither<boolean>;
}

export interface Authenticator {
    /**
     * Allow the handling of requests with no rules
     * @param context The context of the request
     */
    allowNoRulesAccess: (context: AuthorizationContext) => TaskEither<boolean>;

    /**
     * Retrieve the current user from the request
     * @param context The context of the request
     */
    retrieveUser: (context: AuthorizationContext) => TaskEither<User>;
}

export interface NotificationService {
    /**
     * @desc Send a reset password email to the user
     * @param email The email address of the user
     * @param url The URL to redirect to after the password is reset
     * @param token The token to include in the email
     */
    sendResetPasswordEmail(email: string, url: string, token: string): Promise<void>;

    /**
     * @desc Send a verification email to the user
     * @param email The email address of the user
     * @param url The URL to redirect to after the email is verified
     * @param token The token to include in the email
     */
    sendVerificationEmail(email: string, url: string, token: string): Promise<void>;
}

export interface AuthorizationMetadata extends ModuleMetadata {
    inject?: any[];
    useFactory: (...args: any[]) => Promise<Authenticator> | Authenticator;
}

export interface AuthenticationMetadata extends Pick<ModuleMetadata, 'imports'> {
    inject?: any[];
    useFactory: (...args: any[]) => Promise<AuthenticationOptions> | AuthenticationOptions;
}

export interface Permission<Resource extends AppSubject = AppSubject> {
    action: Action;
    resource: Resource;
    field?: KeyOfSubject<Resource>;
}

/**
 * Decorator to retrieve the current user's ability for the current request
 */
export declare const CurrentAbility: {
    WS: () => ParameterDecorator;
    HTTP: () => ParameterDecorator;
};

/**
 * Decorator to retrieve the current user's session for the current request
 */
export declare const CurrentSession: {
    WS: () => ParameterDecorator;
    HTTP: () => ParameterDecorator;
}

/**
 * Decorator to retrieve the current user's session for the current request
 */
export declare const CurrentToken: {
    WS: () => ParameterDecorator;
    HTTP: () => ParameterDecorator;
};

export function createParamDecorator<T>(mapper: ContextMapper<T>): {
    WS: () => ParameterDecorator;
    HTTP: () => ParameterDecorator;
};

/**
 * Decorator to check if the user can perform the given permissions
 * @param permissions The permissions to check
 */
export declare function CanPerform<Resource extends AppSubject>(...permissions: Permission<Resource>[]): ClassDecorator & MethodDecorator;

/**
 * Decorator to describe a class as an authorizer for the application
 */
export declare function Authorizer(): ClassDecorator;

/**
 * Sort the given actions by their priority
 * @param actions The actions to sort
 */
export declare function sortActions(actions: Action[]): Action[];

/**
 * Run the given task and map the result to a success or failure, throwing an error if the task fails
 * @param task The task to map
 * @param logger The logger to log errors with
 */
export function mapTaskEither<DataType>(task: TaskEither<DataType>, logger: LoggerService): Promise<DataType>;

export declare class AuthorizationModule {
    static forRootAsync(metadata: AuthorizationMetadata): DynamicModule;
}

export declare class AuthenticationModule {
    static forRootAsync(metadata: AuthenticationMetadata): DynamicModule;
}

/**
 * Sets up the Nest application with the better-auth authentication module
 * @param AppModule The application module to setup
 */
export async function setupAuth(AppModule: Type): Promise<NestExpressApplication<Server<typeof IncomingMessage, typeof ServerResponse>>>

/**
 * A dummy function to be used to create a better-auth client useful for generating the prisma schema
 */
export function auth(): {handler: (request: Request) => Promise<Response>, api: InferAPI}

export declare class RedirectException extends HttpException {
    constructor(url: string, message: string, status: number);

    /**
     * Handle the exception by redirecting the response
     * @param response The response to redirect
     */
    handle(response: Response): void;
}

export declare class TemporaryRedirectException extends RedirectException {
    constructor(url: string);
}

export declare class PermanentRedirectException extends RedirectException {
    constructor(url: string);
}

export declare class HttpExceptionDto {
    statusCode: number;
    message: string;
    error: string;
}

export declare class HttpExceptionSchema {
    statusCode: number;
    message: string;
    error: string;
}

export declare class AuthorizationHttpGuard implements CanActivate {
    canActivate(context: ExecutionContext): Promise<boolean>;
}

export declare class AuthorizationSocketGuard implements CanActivateSocket {
    canActivate(context: Context): Promise<boolean>;
}

export declare class AuthorizationContext {
    get isSocket (): boolean;

    get isHttp (): boolean;

    get isGraphql (): boolean;

    /**
     * @desc Returns the socket context for the current request
     */
    getSocketContext <Path extends string = string, Event extends PondEventMap = PondEventMap, Presence extends PondPresence = PondPresence, Assigns extends PondAssigns = PondAssigns> (): Context<Path, Event, Presence, Assigns>;

    /**
     * @desc Returns the http context for the current request
     */
    getHttpContext (): ExecutionContext;

    /**
     * @desc Returns the GraphQL context for the current request
     */
    getGraphQLContext(): GqlExecutionContext;

    /**
     * @desc Returns the request object for the current request
     */
    getRequest <DataType = Record<string, unknown>> (): Request & DataType;

    /**
     * @desc Returns the response object for the current request
     */
    getResponse (): Response;

    /**
     * Returns the *type* of the controller class which the current handler belongs to.
     */
    getClass<T = any>(): Type<T>;

    /**
     * Returns a reference to the handler (method) that will be invoked next in the
     * request pipeline.
     */
    getHandler(): Function;

    /**
     * Saves the data to the request or socket context.
     * @param key - The key to save the data under.
     * @param data - The data to save.
     */
    addData<T> (key: string, data: T): void;

    /**
     * Retrieves the data from the request or socket context.
     * @param key - The key to retrieve the data from.
     * @returns The data stored under the key.
     */
    getData<T> (key: string): T | null;

    /**
     * Retrieves the params from the request or socket context.
     * @param key - The key to retrieve the param from.
     * @returns The param stored under the key.
     */
    getParam (key: string): string | null;

    /**
     * Retrieves the query from the request or socket context.
     * @param key - The key to retrieve the query from.
     * @returns The query stored under the key.
     */
    getQuery (key: string): string | null;
}
