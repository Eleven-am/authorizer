import 'reflect-metadata';

export class AuthorizationReflector {
    get<T> (metadataKey: string | symbol, target: any, propertyKey?: string | symbol): T | undefined {
        if (propertyKey) {
            return Reflect.getMetadata(metadataKey, target, propertyKey);
        }

        return Reflect.getMetadata(metadataKey, target);
    }

    getAllAndOverride<T> (metadataKey: string | symbol, targets: [any, any?]): T | undefined {
        for (const [target, propertyKey] of targets) {
            const metadata = Reflect.getMetadata(metadataKey, target, propertyKey);

            if (metadata !== undefined) {
                return metadata;
            }
        }

        return undefined;
    }

    getAllAndMerge<T> (metadataKey: string | symbol, targets: [any, any?][]): T extends any[] ? T : T[] {
        const result: any = [];

        for (const [target, propertyKey] of targets) {
            const metadata = Reflect.getMetadata(metadataKey, target, propertyKey);

            if (metadata) {
                result.push(...(Array.isArray(metadata) ? metadata : [metadata]));
            }
        }

        return result;
    }
}
