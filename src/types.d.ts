import { PureAbility, AbilityBuilder } from '@casl/ability';
import { Subjects, PrismaQuery } from '@casl/prisma';
import { TaskEither } from '@eleven-am/fp';
import { Context } from '@eleven-am/pondsocket-nest';
import { ExecutionContext } from '@nestjs/common';
import { AxiosRequestConfig } from 'axios';
import { ZodType } from 'zod';

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
// eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
export declare function CanPerform<Resource extends AppSubject>(...permissions: Permission<Resource>[]): <TFunction extends Function, Y>(target: TFunction | object, propertyKey?: string | symbol, descriptor?: TypedPropertyDescriptor<Y>) => void;

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
