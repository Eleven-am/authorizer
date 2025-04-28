import { Context, CanActivate as CanActivateSocket } from '@eleven-am/pondsocket-nest';
import { CanActivate, ExecutionContext, Injectable, Logger } from '@nestjs/common';
import { mapTaskEither } from './authorization.constants';
import { AuthorizationService } from './authorization.service';
import {GqlExecutionContext} from "@nestjs/graphql";

@Injectable()
export class AuthorizationHttpGuard implements CanActivate {
    private readonly logger = new Logger(AuthorizationHttpGuard.name);

    constructor (protected readonly authorizationService: AuthorizationService) {}

    canActivate (context: ExecutionContext) {
        const task = this.authorizationService.checkAction(context);

        return mapTaskEither(task, this.logger);
    }
}

@Injectable()
export class AuthorizationSocketGuard implements CanActivateSocket {
    private readonly logger = new Logger(AuthorizationSocketGuard.name);

    constructor (protected readonly authorizationService: AuthorizationService) {}

    canActivate (context: Context) {
        const task = this.authorizationService.checkAction(context);

        return mapTaskEither(task, this.logger);
    }
}
