import { dedupeBy, sortBy } from '@eleven-am/fp';

import { Action } from './authorization.contracts';

export const CAN_PERFORM_KEY = Symbol('CAN_PERFORM_KEY');
export const ABILITY_KEY = 'ABILITY_KEY';
export const AUTHORIZER_KEY = Symbol('AUTHORIZER_KEY');

export function sortActions (actions: Action[]) {
    const mapAction = (action: Action) => {
        switch (action) {
            case Action.Create:
                return {
                    action,
                    value: 0,
                };
            case Action.Read:
                return {
                    action,
                    value: 1,
                };
            case Action.Update:
                return {
                    action,
                    value: 2,
                };
            case Action.Delete:
                return {
                    action,
                    value: 3,
                };
            default:
                return {
                    action,
                    value: -1,
                };
        }
    };

    const mappedActions = dedupeBy(sortBy(actions.map(mapAction), 'value', 'desc'), 'action');

    return mappedActions.map((action) => action.action);
}
