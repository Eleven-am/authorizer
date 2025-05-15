import { AbilityBuilder, ForbiddenError } from '@casl/ability';
import { createPrismaAbility } from '@casl/prisma';
import { TaskEither, createUnauthorizedError } from '@eleven-am/fp';
import { Context } from '@eleven-am/pondsocket-nest';
import { DiscoveryService } from '@golevelup/nestjs-discovery';
import { Injectable, OnModuleInit, ExecutionContext, ForbiddenException, Inject } from '@nestjs/common';
import { Authenticator } from '../types';

import { AUTHORIZER_KEY, CAN_PERFORM_KEY, ABILITY_KEY, AUTHENTICATION_BACKEND } from './authorization.constants';
import { AuthorizationContext } from './authorization.context';
import { WillAuthorize, User, Permission, AppAbilityType } from './authorization.contracts';
import { AuthorizationReflector } from './authorization.reflector';

@Injectable()
export class AuthorizationService implements OnModuleInit {
    private authorizers: WillAuthorize[] = [];

    constructor (
        private readonly discoverService: DiscoveryService,
        private readonly reflector: AuthorizationReflector,
        @Inject(AUTHENTICATION_BACKEND) private readonly authenticator: Authenticator,
    ) {}

    async onModuleInit () {
        const classes = await this.discoverService.providersWithMetaAtKey(AUTHORIZER_KEY);

        this.authorizers = classes.map((provider) => provider.discoveredClass.instance as WillAuthorize);
    }

    checkAction (ctx: ExecutionContext | Context) {
        const context = new AuthorizationContext(ctx);
        const rules = this.getRules(context);

        const action = (user: User) =>  TaskEither.of(user)
            .map((user) => this.defineAbilityFor(user, rules))
            .chain(({ ability, authorizers }) => TaskEither
                .of(authorizers)
                .chainItems((item) => item.authorize(context, ability, rules))
                .ioSync(() => context.addData(ABILITY_KEY, ability))
            )
            .filterItems((item) => !item)
            .filter(
                (items) => Boolean(items.length),
                () => createUnauthorizedError('User is not authorized to access this resource'),
            )
            .map(() => true)

        return this.authenticator
            .retrieveUser(context).orNull()
            .matchTask([
                {
                    predicate: (user) => Boolean(user),
                    run: action,
                },
                {
                    predicate: () => rules.length === 0,
                    run: () => this.authenticator.allowNoRulesAccess(context),
                }
            ])
            .mapError(() => createUnauthorizedError('User is not authenticated'));
    }

    private getRules (context: AuthorizationContext) {
        return this.reflector.getAllAndMerge<Permission[]>(
            CAN_PERFORM_KEY,
            [
                context.getHandler(),
                context.getClass(),
            ],
        );
    }

    private defineAbilityFor (user: User, rules: Permission[]) {
        const { can, cannot, build } = new AbilityBuilder<AppAbilityType>(
            createPrismaAbility,
        );

        try {
            const authorizers = this.authorizers;

            authorizers.forEach((authorizer) => {
                authorizer.forUser(user, {
                    can,
                    cannot,
                });
            });

            const ability = build();

            rules.forEach((rule) => {
                ForbiddenError.from(ability)
                    .throwUnlessCan(
                        rule.action,
                        rule.resource,
                        rule.field,
                    );
            });

            const filteredAuthorizers = authorizers.filter((authorizer): authorizer is Required<WillAuthorize> => 'authorize' in authorizer);

            return {
                ability,
                authorizers: filteredAuthorizers,
            };
        } catch (e) {
            throw new ForbiddenException(e.message);
        }
    }
}
