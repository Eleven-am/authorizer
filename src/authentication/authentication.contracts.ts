import { createZodDto } from '@anatine/zod-nestjs';
import { TaskEither } from '@eleven-am/fp';
import { Details } from 'express-useragent';
import { z } from 'zod';

import { User } from '../authorization/authorization.contracts';

export interface PassKey {
    credentialId: string;
    publicKey: string;
    transports: string[];
    counter: number;
    backedUp: boolean;
    deviceType: 'singleDevice' | 'multiDevice';
}

export interface PassKeyData {
    challenge: string;
    details: Details;
    email: string;
    ip: string;
}

export interface OauthProvider {
    scopes: string[];
    clientId: string;
    clientSecret: string;
    tokenUrl: string;
    authorizeUrl: string;
    userDataUrl: string;
}

export interface RegisterParams {
    email: string;
    username: string;
}

export interface AuthenticationBackendInterface {
    rpName(): string;
    createUser(email: string, username: string): TaskEither<User>;
    getUserByUsername(username: string): TaskEither<User>;
    getUserByEmail(email: string): TaskEither<User>;
    getUserById(userId: string): TaskEither<User>;
    updateUser(user: User): TaskEither<User>;
    deleteUser(user: User): TaskEither<User>;
    doesUserExist(email: string): TaskEither<boolean>;

    getPassKeys(email: string, hostname: string): TaskEither<PassKey[]>;
    getPassKey(email: string, hostname: string, credentialId: string): TaskEither<PassKey>;
    updatePassKey(email: string, hostname: string, credentialId: string, counter: number): TaskEither<PassKey>;
    createPassKey(email: string, hostname: string, passKey: PassKey): TaskEither<unknown>;

    getOauthProvider(oauthId: string): TaskEither<OauthProvider>;
}

const detailsSchema = z.object({
    isMobile: z.boolean().optional(),
    isMobileNative: z.boolean().optional(),
    isTablet: z.boolean().optional(),
    isiPad: z.boolean().optional(),
    isiPod: z.boolean().optional(),
    isiPhone: z.boolean().optional(),
    isAndroid: z.boolean().optional(),
    isBlackberry: z.boolean().optional(),
    isOpera: z.boolean().optional(),
    isIE: z.boolean().optional(),
    isEdge: z.boolean().optional(),
    isIECompatibilityMode: z.boolean().optional(),
    isSafari: z.boolean().optional(),
    isFirefox: z.boolean().optional(),
    isWebkit: z.boolean().optional(),
    isChrome: z.boolean().optional(),
    isKonqueror: z.boolean().optional(),
    isOmniWeb: z.boolean().optional(),
    isSeaMonkey: z.boolean().optional(),
    isFlock: z.boolean().optional(),
    isAmaya: z.boolean().optional(),
    isEpiphany: z.boolean().optional(),
    isDesktop: z.boolean().optional(),
    isWindows: z.boolean().optional(),
    isWindowsPhone: z.boolean().optional(),
    isLinux: z.boolean().optional(),
    isLinux64: z.boolean().optional(),
    isMac: z.boolean().optional(),
    isChromeOS: z.boolean().optional(),
    isBada: z.boolean().optional(),
    isSamsung: z.boolean().optional(),
    isRaspberry: z.boolean().optional(),
    isBot: z.boolean().optional(),
    isCurl: z.boolean().optional(),
    isAndroidTablet: z.boolean().optional(),
    isWinJs: z.boolean().optional(),
    isKindleFire: z.boolean().optional(),
    isSilk: z.boolean().optional(),
    isCaptive: z.boolean().optional(),
    isSmartTV: z.boolean().optional(),
    silkAccelerated: z.boolean().optional(),
    browser: z.string(),
    version: z.string(),
    os: z.string(),
    platform: z.string(),
    geoIp: z.record(z.any()),
    source: z.string(),
});

const passKeySchema = z.object({
    username: z.string(),
    email: z.string().email(),
});

const emailSchema = z.object({
    email: z.string()
        .email(),
});

const mailSchema = z.object({
    mail: z.string()
        .email(),
});

export const profileSchema = z.union([emailSchema, mailSchema]);

export const oauthStateSchema = z.object({
    ip: z.string(),
    details: detailsSchema,
});

export const oauthTokenSchema = z.object({
    access_token: z.string(),
    expires_in: z.number(),
});

const Base64URLString = z.string();
const COSEAlgorithmIdentifier = z.number();
const PublicKeyCredentialType = z.literal('public-key');
const AuthenticatorAttachment = z.enum(['cross-platform', 'platform']);
const ResidentKeyRequirement = z.enum(['discouraged', 'preferred', 'required']);
const UserVerificationRequirement = z.enum(['discouraged', 'preferred', 'required']);
const AttestationConveyancePreference = z.enum(['direct', 'enterprise', 'indirect', 'none']);
const AuthenticatorTransportFuture2 = z.enum(['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb']);

const CredentialPropertiesOutputSchema = z.object({
    rk: z.boolean().optional(),
});

const AuthenticationExtensionsClientOutputsSchema = z.object({
    appid: z.boolean().optional(),
    credProps: CredentialPropertiesOutputSchema.optional(),
    hmacCreateSecret: z.boolean().optional(),
});

const AuthenticatorAssertionResponseJSONSchema = z.object({
    clientDataJSON: Base64URLString,
    authenticatorData: Base64URLString,
    signature: Base64URLString,
    userHandle: Base64URLString.optional(),
});

const AuthenticationResponseJSONSchema = z.object({
    id: Base64URLString,
    rawId: Base64URLString,
    response: AuthenticatorAssertionResponseJSONSchema,
    authenticatorAttachment: AuthenticatorAttachment.optional(),
    clientExtensionResults: AuthenticationExtensionsClientOutputsSchema,
    type: PublicKeyCredentialType,
});

const AuthenticatorAttestationResponseJSONSchema = z.object({
    clientDataJSON: Base64URLString,
    attestationObject: Base64URLString,
    authenticatorData: Base64URLString.optional(),
    transports: z.array(AuthenticatorTransportFuture2).optional(),
    publicKeyAlgorithm: COSEAlgorithmIdentifier.optional(),
    publicKey: Base64URLString.optional(),
});

const RegistrationResponseJSONSchema = z.object({
    id: Base64URLString,
    rawId: Base64URLString,
    response: AuthenticatorAttestationResponseJSONSchema,
    authenticatorAttachment: AuthenticatorAttachment.optional(),
    clientExtensionResults: AuthenticationExtensionsClientOutputsSchema,
    type: PublicKeyCredentialType,
});

const PublicKeyCredentialEntity = z.object({
    name: z.string(),
});

const PublicKeyCredentialRpEntity = PublicKeyCredentialEntity.extend({
    id: z.string().optional(),
});

const PublicKeyCredentialUserEntityJSON = z.object({
    id: z.string(),
    name: z.string(),
    displayName: z.string(),
});

const PublicKeyCredentialParameters = z.object({
    alg: COSEAlgorithmIdentifier,
    type: PublicKeyCredentialType,
});

const PublicKeyCredentialDescriptorJSON = z.object({
    id: Base64URLString,
    type: PublicKeyCredentialType,
    transports: z.array(AuthenticatorTransportFuture2).optional(),
});

const AuthenticatorSelectionCriteria = z.object({
    authenticatorAttachment: AuthenticatorAttachment.optional(),
    requireResidentKey: z.boolean().optional(),
    residentKey: ResidentKeyRequirement.optional(),
    userVerification: UserVerificationRequirement.optional(),
});

const AuthenticationExtensionsClientInputs = z.object({
    appid: z.string().optional(),
    credProps: z.boolean().optional(),
    hmacCreateSecret: z.boolean().optional(),
});

const PublicKeyCredentialCreationOptionsJSON = z.object({
    rp: PublicKeyCredentialRpEntity,
    user: PublicKeyCredentialUserEntityJSON,
    challenge: Base64URLString,
    pubKeyCredParams: z.array(PublicKeyCredentialParameters),
    timeout: z.number().optional(),
    excludeCredentials: z.array(PublicKeyCredentialDescriptorJSON).optional(),
    authenticatorSelection: AuthenticatorSelectionCriteria.optional(),
    attestation: AttestationConveyancePreference.optional(),
    extensions: AuthenticationExtensionsClientInputs.optional(),
});

const PublicKeyCredentialRequestOptionsJSON = z.object({
    challenge: Base64URLString,
    timeout: z.number().optional(),
    rpId: z.string().optional(),
    allowCredentials: z.array(PublicKeyCredentialDescriptorJSON).optional(),
    userVerification: UserVerificationRequirement.optional(),
    extensions: AuthenticationExtensionsClientInputs.optional(),
});

export class PassKeyParams extends createZodDto(passKeySchema) {}
export class AuthenticationResponseJSONParams extends createZodDto(AuthenticationResponseJSONSchema) {}
export class RegistrationResponseJSONParams extends createZodDto(RegistrationResponseJSONSchema) {}
export class PublicKeyCredentialCreationOptionsJSONParams extends createZodDto(PublicKeyCredentialCreationOptionsJSON) {}
export class PublicKeyCredentialRequestOptionsJSONParams extends createZodDto(PublicKeyCredentialRequestOptionsJSON) {}
