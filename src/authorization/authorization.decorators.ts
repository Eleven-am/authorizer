import { Context, createParamDecorator as socketDecorator } from '@eleven-am/pondsocket-nest';
import {
    createParamDecorator as httpDecorator,
    ExecutionContext,
    UnauthorizedException,
    applyDecorators,
    SetMetadata,
    Injectable,
} from '@nestjs/common';
import { ApiBearerAuth, ApiUnauthorizedResponse } from '@nestjs/swagger';

import { CAN_PERFORM_KEY, AUTHORIZER_KEY, ABILITY_KEY } from './authorization.constants';
import { AppSubject, Permission, HttpExceptionSchema, AppAbilityType } from './authorization.contracts';

type ContextMapper<T> = (context: Request & Record<string, any> | Context) => T;


function getRequestBody <T> (mapper: ContextMapper<T>) {
    return (data: void, context: ExecutionContext) => {
        const request = context.switchToHttp().getRequest();

        return mapper(request);
    };
}

export function createParamDecorator<T> (mapper: ContextMapper<T>) {
    const socket = socketDecorator(mapper);
    const http = httpDecorator(getRequestBody(mapper));

    return {
        WS: socket,
        HTTP: http,
    };
}

export const CurrentAbility = createParamDecorator(
    (ctx) => {
        let ability: AppAbilityType | null;

        if (ctx instanceof Context) {
            ability = ctx.getData<AppAbilityType>(ABILITY_KEY);
        } else {
            ability = ctx.ability ?? null;
        }

        if (!ability) {
            throw new UnauthorizedException('No ability found');
        }

        return ability;
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
