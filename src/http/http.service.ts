import { TaskEither, Either, createBadRequestError } from '@eleven-am/fp';
import { HttpService as BaseHttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { AxiosRequestConfig } from 'axios';
import { ZodType } from 'zod';

@Injectable()
export class HttpService {
    constructor (private readonly baseHttpService: BaseHttpService) {}

    getSafe<DataType> (
        url: string,
        schema: ZodType<DataType>,
        options?: AxiosRequestConfig,
    ): TaskEither<DataType> {
        return TaskEither
            .tryCatch(
                () => this.baseHttpService.axiosRef.get(url, options),
                'Failed to get data',
            )
            .map((response) => Either.of(response.data))
            .chain((response) => response.parseSchema(schema).toTaskEither());
    }

    postSafe<DataType> (
        url: string,
        schema: ZodType<DataType>,
        data: unknown,
        options?: AxiosRequestConfig,
    ): TaskEither<DataType> {
        return TaskEither
            .tryCatch(
                () => this.baseHttpService.axiosRef.post(url, data, options),
                'Failed to post data',
            )
            .map((response) => Either.of(response.data))
            .chain((response) => response.parseSchema(schema).toTaskEither());
    }

    apiGet<T> (url: string, options?: AxiosRequestConfig) {
        return TaskEither
            .tryCatch(
                () => this.baseHttpService.axiosRef.get(url, options),
                'Failed to get data',
            )
            .filter(
                (response) => response.status === 200,
                () => createBadRequestError('Failed to get data'),
            )
            .map((response) => response.data as T);
    }
}
