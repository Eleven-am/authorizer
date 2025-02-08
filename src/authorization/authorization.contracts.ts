import { PureAbility, AbilityBuilder } from '@casl/ability';
import { Subjects, PrismaQuery } from '@casl/prisma';
import { TaskEither } from '@eleven-am/fp';
import { Context } from '@eleven-am/pondsocket-nest';
import type { ExecutionContext } from '@nestjs/common';
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

export class HttpExceptionSchema extends createZodDto(httpExceptionSchema) {}
