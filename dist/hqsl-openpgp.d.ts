import type { UTCDate } from "@date-fns/utc";
import { PublicKey, PrivateKey } from "openpgp";
import { HQSL } from "./hqsl";
export type CertificationRange = {
    call: string;
    start: UTCDate;
    end: UTCDate;
    key: PublicKey;
};
export declare class HQSLOpenPGP {
    trustedKeys: PublicKey[];
    keyServers: string[];
    timeout: number;
    constructor(trustedKeys: PublicKey[], keyServers: string[], timeout: number);
    static setup(trustedKeys: Array<string | Uint8Array | PublicKey>, keyServers?: string[], timeout?: number): Promise<HQSLOpenPGP>;
    lookup(query: string): Promise<PublicKey[]>;
    verify(qsl: HQSL): Promise<HQSL>;
    getCertifications(key: PublicKey): Promise<CertificationRange[]>;
    sign(qsl: HQSL, key: PrivateKey, passphrase?: string, signingDate?: Date): Promise<HQSL>;
    publish(key: PublicKey, targetKeyServer?: string): Promise<void>;
}
export declare function callID(c: string): string;
export declare function generateSignerKey(userid: string, calls: string[]): Promise<{
    privateKey: PrivateKey;
    publicKey: PublicKey;
    revocationCertificate: string;
}>;
export declare function listCalls(key: PrivateKey | PublicKey): string[];
export declare function addUserID(key: PrivateKey, callsign: string): Promise<PrivateKey>;
//# sourceMappingURL=hqsl-openpgp.d.ts.map