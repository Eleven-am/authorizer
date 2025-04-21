import { Type, ValidationPipe } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { NestExpressApplication } from '@nestjs/platform-express';
import { AuthenticationService } from "../authentication/authentication.service";
import { join } from "path";
import cookieParser from 'cookie-parser';
import express, { json, urlencoded } from "express";

export async function setupAuth (AppModule: Type) {
    const app = await NestFactory.create<NestExpressApplication>(AppModule);
    const authService = app.get(AuthenticationService);

    const expressApp = express();

    expressApp.all('/api/auth/*path', authService.handler());
    app.use(expressApp);

    app.use(cookieParser());
    app.setBaseViewsDir(join(__dirname, '..', 'views'));
    app.useStaticAssets(join(__dirname, '..', 'public'));
    app.setViewEngine('ejs');
    app.use(json({ limit: '50mb' }));

    app.use(urlencoded({
        extended: true,
        limit: '50mb',
    }));

    app.useGlobalPipes(
        new ValidationPipe({
            transform: true,
            whitelist: true,
        }),
    );

    if (process.env.NODE_ENV === 'development') {
        app.enableCors({
            origin: '*',
            methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
            preflightContinue: false,
            optionsSuccessStatus: 204,
            credentials: true,
        });
    } else {
        app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);
    }

    return app;
}
