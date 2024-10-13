import { BadRequestException, createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import * as useragent from 'express-useragent';

export const WEB_AUTHN_CACHE_KEY = 'WEB_AUTHN_CACHE_KEY';
export const AUTHENTICATION_BACKEND = Symbol('AUTHENTICATION_BACKEND');

export const UserAgent = createParamDecorator(
    (data: unknown, context: ExecutionContext) => {
        const request = context.switchToHttp().getRequest();

        return useragent.parse(request.headers['user-agent']);
    },
);

export const ServerAddress = createParamDecorator(
    (data: unknown, context: ExecutionContext) => {
        const request: Request = context.switchToHttp().getRequest();
        const protocol = request.protocol;
        const host = request.get('host');

        return `${protocol}://${host}`;
    },
);

export const HostAddress = createParamDecorator(
    (data: unknown, context: ExecutionContext) => {
        const request: Request = context.switchToHttp().getRequest();
        const address = request.get('host') || request.get('x-forwarded-host');

        if (!address) {
            throw new BadRequestException('Host address not found');
        }

        const [host] = address.split(':');

        return host;
    },
);

export const PassKeySession = createParamDecorator(
    (data: unknown, context: ExecutionContext) => {
        const request: Request = context.switchToHttp().getRequest();
        const cookie = request.cookies[WEB_AUTHN_CACHE_KEY];

        if (!cookie) {
            throw new BadRequestException('Passkey not found');
        }

        return JSON.parse(Buffer.from(cookie, 'base64').toString());
    },
);
