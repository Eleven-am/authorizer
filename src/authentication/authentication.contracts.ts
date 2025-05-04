import { PrismaClient } from "@prisma/client";
import { ModuleMetadata } from "@nestjs/common";

interface OAUTH2Config {
    clientId: string;
    clientSecret: string;
}

interface ApplicationConfig {
    name: string;
    secret: string;
    version: string;
    address: string;
    description: string;
    rpId: string;
    rpName: string;
}

interface PrismaAdapter {
    provider: "sqlite" | "cockroachdb" | "mysql" | "postgresql" | "sqlserver" | "mongodb";
    client: PrismaClient;
}

interface NotificationService {
    sendResetPasswordEmail(email: string, url: string, token: string): Promise<void>;
    sendVerificationEmail(email: string, url: string, token: string): Promise<void>;
}

export interface AuthenticationOptions {
    google?: OAUTH2Config;
    github?: OAUTH2Config;
    application: ApplicationConfig;
    notification: NotificationService;
    database: PrismaAdapter;
    trustedOrigins: string[];
}

export interface AsyncMetadata extends Pick<ModuleMetadata, 'imports'> {
    inject?: any[];
    useFactory: (...args: any[]) => Promise<AuthenticationOptions> | AuthenticationOptions;
}
