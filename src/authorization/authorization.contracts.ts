import { PureAbility, AbilityBuilder } from '@casl/ability';
import { Subjects, PrismaQuery } from '@casl/prisma';
import { TaskEither } from '@eleven-am/fp';
import { Context } from '@eleven-am/pondsocket-nest';
import type { ExecutionContext } from '@nestjs/common';
import { ApiProperty } from '@nestjs/swagger';
import { IsNumber } from 'class-validator';

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
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface AuthKey {}

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

export class HttpExceptionSchema {
    @IsNumber()
    @ApiProperty({
        description: 'The status code of the error',
        example: 400,
    })
    statusCode: number;

    @ApiProperty({
        description: 'The message of the error',
        example: 'Bad Request',
    })
    message: string;

    @ApiProperty({
        description: 'The error message',
        example: 'The request was malformed',
    })
    error: string;
}
