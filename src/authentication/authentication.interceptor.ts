import { TaskEither } from '@eleven-am/fp';
import { CallHandler, ExecutionContext, Injectable, Logger, NestInterceptor } from '@nestjs/common';
import { from, of, switchMap } from 'rxjs';
import { mapTaskEither } from "../authorization/authorization.constants";

@Injectable()
export class AuthenticationInterceptor implements NestInterceptor {
    private readonly logger = new Logger(AuthenticationInterceptor.name);

    intercept(_: ExecutionContext, next: CallHandler) {
        return next.handle()
            .pipe(switchMap((value) => this.project(value)));
    }

    private project(value: any) {
        if (value instanceof TaskEither) {
            return from(mapTaskEither(value, this.logger));
        }

        return of(value);
    }
}
