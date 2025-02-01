import 'reflect-metadata';

export class AuthorizationReflector {
    get<T> (metadataKey: string | symbol, target: any): T | undefined {
        return Reflect.getMetadata(metadataKey, target);
    }

    getAllAndOverride<T> (metadataKey: string | symbol, targets: any[]): T | undefined {
        for (const target of targets) {
            const metadata = Reflect.getMetadata(metadataKey, target);

            if (metadata !== undefined) {
                return metadata;
            }
        }

        return undefined;
    }

    getAllAndMerge<T> (metadataKey: string | symbol, targets: any[]): T extends any[] ? T : T[] {
        const result: any[] = [];

        for (const target of targets) {
            const metadata = Reflect.getMetadata(metadataKey, target);

            if (metadata) {
                result.push(...(Array.isArray(metadata) ? metadata : [metadata]));
            }
        }

        return result as T extends any[] ? T : T[];
    }
}
