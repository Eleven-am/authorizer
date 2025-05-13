import {NotFoundException} from "@nestjs/common";
import { createParamDecorator } from "../authorization/authorization.decorators";
import {AuthenticationService} from "./authentication.service";
import {Authenticator, AuthorizationMetadata} from "../types";

export const CURRENT_SESSION_KEY = 'CURRENT_SESSION_KEY';
export const CURRENT_TOKEN_KEY = 'CURRENT_TOKEN_KEY';

export function filterNull<T> (value: T | null | undefined, error: string): T {
    if (value === null || value === undefined) {
        throw new NotFoundException(error);
    }

    return value;
}

export const CurrentSession = createParamDecorator(
    (ctx) => filterNull(
        ctx.getData(CURRENT_SESSION_KEY),
        'Session not found',
    )
);

export const CurrentToken = createParamDecorator(
    (ctx) => filterNull(
        ctx.getData(CURRENT_TOKEN_KEY),
        'Token not found',
    )
);

export const authenticationBackend: AuthorizationMetadata = {
    inject: [AuthenticationService],
    useFactory: (authenticationService: AuthenticationService): Authenticator => ({
        allowNoRulesAccess: (context) => authenticationService.allowNoRulesAccess(context),
        retrieveUser: (context) => authenticationService.getSession(context),
    })
};
