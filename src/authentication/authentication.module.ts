import {DynamicModule, Provider} from '@nestjs/common';
import {AsyncMetadata} from "./authentication.contracts";
import {AuthenticationService} from "./authentication.service";

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
}
