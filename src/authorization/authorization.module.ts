import { DiscoveryModule } from '@golevelup/nestjs-discovery';
import { Module, Global } from '@nestjs/common';

import { AuthorizationService } from './authorization.service';

@Global()
@Module({
    imports: [DiscoveryModule],
    providers: [AuthorizationService],
    exports: [AuthorizationService],
})
export class AuthorizationModule {}
