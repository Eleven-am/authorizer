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
import { AuthorizationContext } from './authorization.context';
import { AppSubject, Permission, HttpExceptionSchema, AppAbilityType } from './authorization.contracts';

type ContextMapper<Output> = (context: AuthorizationContext) => Output;

function socketMapper <T> (mapper: ContextMapper<T>) {
    return (data: void, context: Context) => mapper(new AuthorizationContext(context));
}

function httpMapper <T> (mapper: ContextMapper<T>) {
    return (data: void, context: ExecutionContext) => mapper(new AuthorizationContext(context));
}

export function createParamDecorator<T> (mapper: ContextMapper<T>) {
    const socket = socketDecorator(socketMapper(mapper));
    const http = httpDecorator(httpMapper(mapper));

    return {
        WS: socket,
        HTTP: http,
    };
}

export const CurrentAbility = createParamDecorator(
    (ctx) => {
        const ability = ctx.getData<AppAbilityType>(ABILITY_KEY);

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
