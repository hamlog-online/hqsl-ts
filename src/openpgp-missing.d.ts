/* Definitions we need which are missing from openpgp.d.ts as of 6.1.0. */

import "openpgp";

declare module "openpgp" {

    export class User {
        constructor(
            userPacket: UserIDPacket | UserAttributePacket,
            mainKey: Key
        );
        public verifyCertificate(
            certificate: SignaturePacket,
            verificationKeys: Array<PublicKey>,
            date?: Date,
            config?: PartialConfig
        ): Promise<true | null>;
        public verify(date?: Date, config?: PartialConfig): Promise<true>;
    }

    export interface Config {
        preferredHashAlgorithm: enums.hash;
        preferredSymmetricAlgorithm: enums.symmetric;
        preferredCompressionAlgorithm: enums.compression;
        showVersion: boolean;
        showComment: boolean;
        aeadProtect: boolean;
        allowUnauthenticatedMessages: boolean;
        allowUnauthenticatedStream: boolean;
        minRSABits: number;
        passwordCollisionCheck: boolean;
        ignoreUnsupportedPackets: boolean;
        ignoreMalformedPackets: boolean;
        versionString: string;
        commentString: string;
        allowInsecureDecryptionWithSigningKeys: boolean;
        allowInsecureVerificationWithReformattedKeys: boolean;
        allowMissingKeyFlags: boolean;
        constantTimePKCS1Decryption: boolean;
        constantTimePKCS1DecryptionSupportedSymmetricAlgorithms: Set<enums.symmetric>;
        v6Keys: boolean;
        enableParsingV5Entities: boolean;
        preferredAEADAlgorithm: enums.aead;
        aeadChunkSizeByte: number;
        s2kType: enums.s2k.iterated | enums.s2k.argon2;
        s2kIterationCountByte: number;
        s2kArgon2Params: { passes: number, parallelism: number; memoryExponent: number; };
        maxUserIDLength: number;
        knownNotations: string[];
        useEllipticFallback: boolean;
        rejectHashAlgorithms: Set<enums.hash>;
        rejectMessageHashAlgorithms: Set<enums.hash>;
        rejectPublicKeyAlgorithms: Set<enums.publicKey>;
        rejectCurves: Set<enums.curve>;
        // This was missing.
        nonDeterministicSignaturesViaNotation: boolean;
    }      
}
