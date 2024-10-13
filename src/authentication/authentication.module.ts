import { DynamicModule, Provider } from '@nestjs/common';

import { HttpModule } from '../http/http.module';
import { AsyncMetadata } from '../types';
import { AUTHENTICATION_BACKEND } from './authentication.constants';
import { AuthenticationService } from './authentication.service';


export class AuthenticationModule {
    static forRoot ({
        providers,
        imports,
        exports,
        inject,
        useFactory,
        controllers,
    }: AsyncMetadata): DynamicModule {
        const provider: Provider = {
            provide: AUTHENTICATION_BACKEND,
            inject,
            useFactory,
        };

        return {
            controllers,
            module: AuthenticationModule,
            imports: [HttpModule, ...(imports || [])],
            exports: [AuthenticationService, ...(exports || [])],
            providers: [provider, AuthenticationService, ...(providers || [])],
        };
    }
}
