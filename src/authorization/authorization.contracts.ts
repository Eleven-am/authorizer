import { PureAbility, AbilityBuilder } from '@casl/ability';
import { Subjects, PrismaQuery } from '@casl/prisma';
import { TaskEither } from '@eleven-am/fp';
import { Context } from '@eleven-am/pondsocket-nest';
import { ExecutionContext, HttpException, HttpStatus } from '@nestjs/common';
import { ApiProperty } from '@nestjs/swagger';
import { Response } from 'express';
import { createZodDto } from 'nestjs-zod';
import { z } from 'zod';


export enum Action {
    Create = 'create',
    Read = 'read',
    Update = 'update',
    Delete = 'delete',
    Manage = 'manage',
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface SubjectTypes {}
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface User {}

export type AppSubject = Subjects<SubjectTypes>;

type KeyOfSubject<subject extends AppSubject> =
    subject extends keyof SubjectTypes ? keyof SubjectTypes[subject] : subject;

export type AppAbilityType = PureAbility<[Action, AppSubject], PrismaQuery>;

export type RuleBuilder = Pick<AbilityBuilder<AppAbilityType>, 'can' | 'cannot'>;

export interface WillAuthorize {
    forUser(user: User, builder: RuleBuilder): void;
    checkHttpAction?(
        ability: AppAbilityType,
        rules: Permission[],
        context: ExecutionContext,
    ): TaskEither<boolean>;
    checkSocketAction?(
        ability: AppAbilityType,
        rules: Permission[],
        context: Context,
    ): TaskEither<boolean>;
}

export interface Permission<Resource extends AppSubject = AppSubject> {
    action: Action;
    resource: Resource;
    field?: KeyOfSubject<Resource>;
}

const httpExceptionSchema = z.object({
    statusCode: z.number(),
    message: z.string(),
    error: z.string(),
});

export class HttpExceptionDto extends createZodDto(httpExceptionSchema) {}

export class RedirectException extends HttpException {
    constructor (private readonly url: string, message: string, status: number) {
        super(message, status);
    }

    public handle (response: Response) {
        response.redirect(this.url);
    }
}

export class TemporaryRedirectException extends RedirectException {
    constructor (url: string) {
        super(url, `Temporary redirect to ${url}`, HttpStatus.TEMPORARY_REDIRECT);
    }
}

export class PermanentRedirectException extends RedirectException {
    constructor (url: string) {
        super(url, `Permanent redirect to ${url}`, HttpStatus.PERMANENT_REDIRECT);
    }
}

export class HttpExceptionSchema {
    @ApiProperty({
        example: 404,
        description: 'HTTP status code',
        type: Number,
    })
    statusCode: number;

    @ApiProperty({
        example: 'Not Found',
        description: 'HTTP status message',
        type: String,
    })
    message: string;

    @ApiProperty({
        example: 'The requested resource was not found',
        description: 'HTTP status error',
        type: String,
    })
    error: string;
}
