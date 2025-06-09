import { TaskEither } from '@eleven-am/fp';
import { CallHandler, ExecutionContext, Injectable, Logger, NestInterceptor } from '@nestjs/common';
import { from, of, switchMap } from 'rxjs';

import { mapTaskEither } from './authorization.constants';

@Injectable()
export class AuthorizationInterceptor implements NestInterceptor {
    private readonly logger = new Logger(AuthorizationInterceptor.name);

    intercept (_: ExecutionContext, next: CallHandler) {
        return next.handle()
            .pipe(switchMap((value) => this.project(value)));
    }

    private project (value: any) {
        if (value instanceof TaskEither) {
            return from(mapTaskEither(value, this.logger));
        }

        return of(value);
    }
}
