import { dedupeBy, sortBy, Failed, TaskEither, hasError } from '@eleven-am/fp';
import {
    HttpException,
    HttpStatus,
    BadRequestException,
    UnauthorizedException,
    ForbiddenException,
    NotFoundException,
    InternalServerErrorException,
    LoggerService,
} from '@nestjs/common';

import { Action, TemporaryRedirectException, PermanentRedirectException } from './authorization.contracts';

export const CAN_PERFORM_KEY = Symbol('CAN_PERFORM_KEY');
export const ABILITY_KEY = 'ABILITY_KEY';
export const AUTHORIZER_KEY = Symbol('AUTHORIZER_KEY');
export const AUTHENTICATION_BACKEND = Symbol('AUTHENTICATION_BACKEND');

export function sortActions (actions: Action[]) {
    const mapAction = (action: Action) => {
        switch (action) {
            case Action.Create:
                return {
                    action,
                    value: 0,
                };
            case Action.Read:
                return {
                    action,
                    value: 1,
                };
            case Action.Update:
                return {
                    action,
                    value: 2,
                };
            case Action.Delete:
                return {
                    action,
                    value: 3,
                };
            default:
                return {
                    action,
                    value: -1,
                };
        }
    };

    const mappedActions = dedupeBy(sortBy(actions.map(mapAction), 'value', 'desc'), 'action');

    return mappedActions.map((action) => action.action);
}

function mapFailedToException (error: Failed): HttpException {
    if (error.error instanceof HttpException) {
        return error.error;
    }

    switch (error.code) {
        case HttpStatus.BAD_REQUEST:
            return new BadRequestException(error.error.message);
        case HttpStatus.UNAUTHORIZED:
            return new UnauthorizedException(error.error.message);
        case HttpStatus.FORBIDDEN:
            return new ForbiddenException(error.error.message);
        case HttpStatus.NOT_FOUND:
            return new NotFoundException(error.error.message);
        case HttpStatus.INTERNAL_SERVER_ERROR:
            return new InternalServerErrorException(error.error.message);
        case HttpStatus.TEMPORARY_REDIRECT:
            return new TemporaryRedirectException(error.error.message);
        case HttpStatus.PERMANENT_REDIRECT:
            return new PermanentRedirectException(error.error.message);
        default:
            return new HttpException(error.error.message, error.code);
    }
}

export async function mapTaskEither<T> (task: TaskEither<T>, logger: LoggerService): Promise<T> {
    const result = await task.toResult();

    if (hasError(result)) {
        logger.error(result.error.message);
        throw mapFailedToException(result);
    }

    return result.data;
}
