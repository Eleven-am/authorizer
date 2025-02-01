import { AbilityBuilder, ForbiddenError } from '@casl/ability';
import { createPrismaAbility } from '@casl/prisma';
import { TaskEither, createUnauthorizedError } from '@eleven-am/fp';
import { Context } from '@eleven-am/pondsocket-nest';
import { DiscoveryService } from '@golevelup/nestjs-discovery';
import { Injectable, OnModuleInit, ExecutionContext, ForbiddenException, Inject } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { AUTHORIZER_KEY, CAN_PERFORM_KEY, ABILITY_KEY } from './authorization.constants';
import { WillAuthorize, User, Permission, AppAbilityType } from './authorization.contracts';

@Injectable()
export class AuthorizationService implements OnModuleInit {
    private authorizers: WillAuthorize[] = [];

    constructor (
        @Inject(Reflector)
        private readonly reflector: Reflector,
        private readonly discoverService: DiscoveryService,
    ) {}

    async onModuleInit () {
        const classes = await this.discoverService.providersWithMetaAtKey(AUTHORIZER_KEY);

        this.authorizers = classes.map((provider) => provider.discoveredClass.instance as WillAuthorize);
    }

    checkHttpAction (user: User | null, context: ExecutionContext) {
        const rules = this.getRules(context);
        const request = context.switchToHttp().getRequest();

        if (rules.length === 0) {
            return TaskEither.of(true);
        }

        return TaskEither
            .fromNullable(user)
            .mapError(() => createUnauthorizedError('User is not authenticated'))
            .map((user) => this.defineAbilityFor(user, rules))
            .map(({ ability, authorizers }) => {
                const hasHttpAction = authorizers.filter((authorizer): authorizer is Required<WillAuthorize> => 'checkHttpAction' in authorizer);
                const tasks = hasHttpAction.map((authorizer) => authorizer.checkHttpAction(ability, rules, context));

                request.ability = ability;

                return tasks;
            })
            .chain((tasks) => TaskEither.all(...tasks))
            .map(() => true);
    }

    checkSocketAction (user: User | null, context: Context) {
        const rules = this.getRules(context);

        return TaskEither
            .fromNullable(user)
            .mapError(() => createUnauthorizedError('User is not authenticated'))
            .map((user) => this.defineAbilityFor(user, rules))
            .map(({ ability, authorizers }) => {
                const hasSocketAction = authorizers.filter((authorizer): authorizer is Required<WillAuthorize> => 'checkSocketAction' in authorizer);
                const tasks = hasSocketAction.map((authorizer) => authorizer.checkSocketAction(ability, rules, context));

                context.addData<AppAbilityType>(ABILITY_KEY, ability);

                return tasks;
            })
            .chain((tasks) => TaskEither.all(...tasks))
            .map(() => true);
    }

    private getRules (context: ExecutionContext | Context) {
        const acceptableRulesMethods =
            this.reflector.get<Permission[]>(CAN_PERFORM_KEY, context.getHandler()) ??
            [];
        const acceptableRulesClass =
            this.reflector.get<Permission[]>(CAN_PERFORM_KEY, context.getClass()) ??
            [];

        return ([] as Permission[]).concat(
            acceptableRulesMethods,
            acceptableRulesClass,
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
}
