import { PureAbility, AbilityBuilder } from '@casl/ability';
import { Subjects, PrismaQuery } from '@casl/prisma';
import { TaskEither } from '@eleven-am/fp';
import { Context, CanActivate as CanActivateSocket } from '@eleven-am/pondsocket-nest';
import { ExecutionContext, DynamicModule, ModuleMetadata, LoggerService, CanActivate } from '@nestjs/common';

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

export type ContextMapper<T> = (context: Request & Record<string, any> | Context) => T;

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

export interface Authenticator {
    /**
     * Allow the handling of requests with no rules
     * @param context The context of the request
     */
    allowNoRulesAccess: (context: ExecutionContext | Context) => TaskEither<boolean>;

    /**
     * Retrieve the current user from the request
     * @param context The context of the request
     */
    retrieveUser: (context: ExecutionContext | Context) => TaskEither<User>;
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
// eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
export declare function CanPerform<Resource extends AppSubject>(...permissions: Permission<Resource>[]): ClassDecorator & MethodDecorator;

/**
 * Decorator to describe a class as an authorizer for the application
 */
// eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
export declare function Authorizer(): <TFunction extends Function, Y>(target: TFunction | object, propertyKey?: string | symbol, descriptor?: TypedPropertyDescriptor<Y>) => void;

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

export declare class AuthorizationHttpGuard implements CanActivate {}

export class AuthorizationSocketGuard implements CanActivateSocket {}
