import { Context, createParamDecorator as socketDecorator, ParamDecoratorCallback } from '@eleven-am/pondsocket-nest';
import {
    createParamDecorator as httpDecorator,
    ExecutionContext,
    UnauthorizedException,
    applyDecorators,
    SetMetadata,
    Injectable,
    BadRequestException,
} from '@nestjs/common';
import { ApiBearerAuth, ApiUnauthorizedResponse } from '@nestjs/swagger';

import { CAN_PERFORM_KEY, AUTHORIZER_KEY, ABILITY_KEY } from './authorization.constants';
import { AppSubject, Permission, HttpExceptionSchema, AppAbilityType } from './authorization.contracts';

type ContextMapper<T> = (context: Request & Record<string, any> | Context) => T;

function filterFalsy <T> (model: string, mapper: ContextMapper<T>): ParamDecoratorCallback<void, unknown> {
    return (_, context) => {
        const result = mapper(context);

        if (!result) {
            throw new BadRequestException(`${model} not found`);
        }

        return result;
    };
}

function getRequestBody <T> (model: string, mapper: ContextMapper<T>) {
    return (data: void, context: ExecutionContext) => {
        const request = context.switchToHttp().getRequest();

        return filterFalsy(model, mapper)(data, request, null);
    };
}

export function createParamDecorator<T> (model: string, mapper: ContextMapper<T>) {
    const socket = socketDecorator(filterFalsy(model, mapper));
    const http = httpDecorator(getRequestBody(model, mapper));

    return {
        WS: socket,
        HTTP: http,
    };
}

export const CurrentAbility = createParamDecorator(
    'Ability',
    (ctx) => {
        let ability: AppAbilityType | null;

        if (ctx instanceof Context) {
            ability = ctx.getData<AppAbilityType>(ABILITY_KEY);
        } else {
            ability = ctx.ability ?? null;
        }

        if (ability) {
            return ability;
        }

        throw new UnauthorizedException();
    },
);

export function CanPerform<Resource extends AppSubject> (
    ...permissions: Permission<Resource>[]
) {
    return applyDecorators(
        SetMetadata(CAN_PERFORM_KEY, permissions),
        ApiBearerAuth(),
        ApiUnauthorizedResponse({
            description: 'Unauthorized',
            type: HttpExceptionSchema,
        }),
    );
}

export function Authorizer () {
    return applyDecorators(SetMetadata(AUTHORIZER_KEY, true), Injectable());
}
