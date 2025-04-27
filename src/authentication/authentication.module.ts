import {DynamicModule, Provider} from '@nestjs/common';
import {AsyncMetadata} from "./authentication.contracts";
import {AUTHENTICATION_BACKEND} from "../authorization/authorization.constants";
import {DiscoveryModule} from "@golevelup/nestjs-discovery";
import {AuthorizationService} from "../authorization/authorization.service";
import {AuthorizationReflector} from "../authorization/authorization.reflector";
import {AuthenticationService} from "./authentication.service";
import {AuthorizationSocketGuard} from "../authorization/authorization.guards";
import {Authenticator} from "../types";
import {PondSocketModule} from "@eleven-am/pondsocket-nest";

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

        const authorizationProvider: Provider = {
            provide: AUTHENTICATION_BACKEND,
            inject: [AuthenticationService],
            useFactory: (authenticationService: AuthenticationService): Authenticator => ({
                allowNoRulesAccess: (context) => authenticationService.allowNoRulesAccess(context),
                retrieveUser: (context) => authenticationService.getSession(context),
            })
        }

        return {
            global: true,
            module: AuthenticationModule,
            imports: [
                ...(imports || []),
                DiscoveryModule,
                PondSocketModule.forRootAsync({
                    inject: [AuthenticationService],
                    guards: [AuthorizationSocketGuard],
                    useFactory: (authenticationService: AuthenticationService) => authenticationService.getRedisOptions()
                }),
            ],
            providers: [
                authenticationProvider,
                authorizationProvider,
                AuthorizationReflector,
                AuthorizationService,
            ],
            exports: [AuthenticationService, AuthorizationService],
        };
    }
}
