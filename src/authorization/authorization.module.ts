import { DiscoveryModule } from '@golevelup/nestjs-discovery';
import { DynamicModule, Provider } from '@nestjs/common';

import { AuthorizationMetadata } from '../types';
import { AUTHENTICATION_BACKEND } from './authorization.constants';
import { AuthorizationReflector } from './authorization.reflector';
import { AuthorizationService } from './authorization.service';

export class AuthorizationModule {
    static forRootAsync ({
        providers,
        imports,
        exports,
        inject,
        useFactory,
    }: AuthorizationMetadata): DynamicModule {
        const provider: Provider = {
            provide: AUTHENTICATION_BACKEND,
            inject,
            useFactory,
        };

        return {
            global: true,
            module: AuthorizationModule,
            imports: [DiscoveryModule, ...(imports || [])],
            exports: [AuthorizationService, ...(exports || [])],
            providers: [provider, AuthorizationReflector, AuthorizationService, ...(providers || [])],
        };
    }
}
