import { AbilityBuilder, ForbiddenError } from '@casl/ability';
import { createPrismaAbility } from '@casl/prisma';
import { TaskEither, createUnauthorizedError } from '@eleven-am/fp';
import { Context } from '@eleven-am/pondsocket-nest';
import { DiscoveryService } from '@golevelup/nestjs-discovery';
import { Injectable, OnModuleInit, ExecutionContext, ForbiddenException, Inject } from '@nestjs/common';
import { Authenticator } from '../types';

import { AUTHORIZER_KEY, CAN_PERFORM_KEY, ABILITY_KEY, AUTHENTICATION_BACKEND } from './authorization.constants';
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

    checkHttpAction (context: ExecutionContext) {
        const rules = this.getRules(context);
        const request = context.switchToHttp().getRequest();

        const httpAction = (user: User)=>  TaskEither
            .of(user)
            .map((user) => this.defineAbilityFor(user, rules))
            .map(({ ability, authorizers }) => {
                const hasHttpAction = authorizers.filter((authorizer): authorizer is Required<WillAuthorize> => 'checkHttpAction' in authorizer);
                const tasks = hasHttpAction.map((authorizer) => authorizer.checkHttpAction(ability, rules, context));

                request.ability = ability;

                return tasks;
            })
            .chain((tasks) => TaskEither.all(...tasks))
            .map(() => true);

        return this.performAction(context, rules, httpAction);
    }

    checkSocketAction (context: Context) {
        const rules = this.getRules(context);

        const socketAction = (user: User) => TaskEither
            .of(user)
            .map((user) => this.defineAbilityFor(user, rules))
            .map(({ ability, authorizers }) => {
                const hasSocketAction = authorizers.filter((authorizer): authorizer is Required<WillAuthorize> => 'checkSocketAction' in authorizer);
                const tasks = hasSocketAction.map((authorizer) => authorizer.checkSocketAction(ability, rules, context));

                context.addData<AppAbilityType>(ABILITY_KEY, ability);

                return tasks;
            })
            .chain((tasks) => TaskEither.all(...tasks))
            .map(() => true);

        return this.performAction(context, rules, socketAction);
    }

    private getRules (context: ExecutionContext | Context) {
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

            return {
                ability,
                authorizers,
            };
        } catch (e) {
            throw new ForbiddenException(e.message);
        }
    }

    private performAction (context: ExecutionContext | Context, rules: Permission[], authorizeTask: (user: User) => TaskEither<boolean>) {
        return this.authenticator.retrieveUser(context)
            .chain(authorizeTask)
            .orElse(() => TaskEither
                .of(rules)
                .filter(
                    (rules) => rules.length === 0,
                    () => createUnauthorizedError('User is not authenticated'),
                )
                .chain(() => this.authenticator.allowNoRulesAccess(context))
            )
            .mapError(() => createUnauthorizedError('User is not authenticated'));
    }
}
