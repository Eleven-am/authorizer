import { DiscoveryModule } from '@golevelup/nestjs-discovery';
import { Module, Global } from '@nestjs/common';

import { AuthorizationReflector } from './authorization.reflector';
import { AuthorizationService } from './authorization.service';

@Global()
@Module({
    imports: [DiscoveryModule],
    providers: [AuthorizationReflector, AuthorizationService],
    exports: [AuthorizationService],
})
export class AuthorizationModule {}
