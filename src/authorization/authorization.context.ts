import { Context } from '@eleven-am/pondsocket-nest';
import { ExecutionContext, Type } from '@nestjs/common';
import { Request, Response } from 'express';

export class AuthorizationContext {
    readonly #socketContext: Context | null;
    readonly #httpContext: ExecutionContext | null;

    constructor (context: ExecutionContext | Context) {
        if (context instanceof Context) {
            this.#socketContext = context;
            this.#httpContext = null;
        } else {
            this.#socketContext = null;
            this.#httpContext = context;
        }
    }

    get socketContext (): Context {
        if (this.#socketContext) {
            return this.#socketContext;
        }

        throw new Error('Socket context is not available');
    }

    get httpContext (): ExecutionContext {
        if (this.#httpContext) {
            return this.#httpContext;
        }

        throw new Error('HTTP context is not available');
    }

    get isSocket (): boolean {
        return Boolean(this.#socketContext);
    }

    get isHttp (): boolean {
        return Boolean(this.#httpContext);
    }

    get request (): Request & Record<string, unknown> {
        if (this.#httpContext) {
            return this.#httpContext.switchToHttp().getRequest();
        }

        throw new Error('HTTP request is not available');
    }

    get response (): Response {
        if (this.#httpContext) {
            return this.#httpContext.switchToHttp().getResponse();
        }

        throw new Error('HTTP response is not available');
    }

    /**
     * Returns the *type* of the controller class which the current handler belongs to.
     */
    getClass<T = any>(): Type<T> {
        if (this.#httpContext) {
            return this.#httpContext.getClass();
        }

        return this.#socketContext!.getClass();
    }

    /**
     * Returns a reference to the handler (method) that will be invoked next in the
     * request pipeline.
     */
    getHandler(): Function {
        if (this.#httpContext) {
            return this.#httpContext.getHandler();
        }

        return this.#socketContext!.getHandler();
    }

    /**
     * Saves the data to the request or socket context.
     * @param key - The key to save the data under.
     * @param data - The data to save.
     */
    addData<T> (key: string, data: T): void {
        if (this.#httpContext) {
            this.#httpContext.switchToHttp().getRequest()[key] = data;
        } else {
            this.#socketContext!.addData(key, data);
        }
    }

    /**
     * Retrieves the data from the request or socket context.
     * @param key - The key to retrieve the data from.
     * @returns The data stored under the key.
     */
    getData<T> (key: string): T | null {
        if (this.#httpContext) {
            return this.#httpContext.switchToHttp()
                .getRequest()[key] ?? null;
        }

        return this.#socketContext!.getData(key);
    }
}


