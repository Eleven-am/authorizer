import {DynamicModule, Provider} from '@nestjs/common';
import {AsyncMetadata} from "./authentication.contracts";
import {AuthenticationService} from "./authentication.service";
import {PondSocketModule} from "@eleven-am/pondsocket-nest";
import {AuthorizationSocketGuard} from "../authorization/authorization.guards";
import {AuthorizationModule} from "../authorization/authorization.module";
import {authenticationBackend} from "./authentication.constants";

export class AuthenticationModule {
    static forRootAsync({
        imports,
        inject,
        useFactory,
    }: AsyncMetadata): DynamicModule {
        const authenticationProvider: Provider = {
            inject,
            provide: AuthenticationService,
            useFactory: async (...args: any[]) => {
                const options = await useFactory(...args);
                return new AuthenticationService(options);
            },
        }

        return {
            global: true,
            module: AuthenticationModule,
            imports: imports,
            providers: [authenticationProvider],
            exports: [AuthenticationService],
        };
    }

    static forRootWithAuthorization(config: AsyncMetadata): DynamicModule {
        const pondSocketModule = PondSocketModule.forRoot({
            isExclusiveSocketServer: false,
            guards: [AuthorizationSocketGuard],
        });

        const authorizationModule = AuthorizationModule.forRootAsync(authenticationBackend);

        const imports = [
            ...(config.imports || []),
            pondSocketModule,
            authorizationModule,
        ];

        return this.forRootAsync({
            ...config,
            imports,
        })
    }
}
