import { PureAbility, AbilityBuilder } from '@casl/ability';
import { Subjects, PrismaQuery } from '@casl/prisma';
import { TaskEither } from '@eleven-am/fp';
import { Context, CanActivate as CanActivateSocket } from '@eleven-am/pondsocket-nest';
import { ExecutionContext, DynamicModule, ModuleMetadata, LoggerService, CanActivate, Type } from '@nestjs/common';
import { Response, Request } from 'express';

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

export interface AsyncMetadata extends ModuleMetadata {
    inject?: any[];
    useFactory: (...args: any[]) => Promise<Authenticator> | Authenticator;
}

export interface Permission<Resource extends AppSubject = AppSubject> {
    action: Action;
    resource: Resource;
    field?: KeyOfSubject<Resource>;
}

/**
 * Decorator to retrieve the current user's ability for the current http request
 */
export declare const CurrentAbility: {
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
    static forRootAsync(metadata: AsyncMetadata): DynamicModule;
}

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
    get socketContext (): Context;

    get httpContext (): ExecutionContext;

    get isSocket (): boolean;

    get isHttp (): boolean;

    get request (): Request;

    get response (): Response;

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
}
