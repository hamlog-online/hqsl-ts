import type { UTCDate } from "@date-fns/utc";
import type { HQSLVerification } from "./hqsl-verification";
export declare const callsignRe: RegExp;
export declare const gridRe: RegExp;
export declare const cardRe: RegExp;
export declare class HQSL {
    from?: string;
    where?: string;
    to?: string;
    when?: UTCDate;
    signal?: string;
    freq?: number;
    mode?: string;
    extra?: string;
    reserved?: string;
    signature?: Uint8Array;
    verification?: HQSLVerification;
    constructor(fields?: {
        from: string;
        where: string;
        to: string;
        when: UTCDate;
        signal?: string;
        freq: number;
        mode: string;
        extra?: string;
    });
    static fromString(s: string): HQSL;
    get band(): string;
    get hamDate(): string;
    get displayDate(): string;
    get signedData(): string;
    toString(): string;
    toADIF(): string;
    static fromADIF(s: string, call: string, grid: string): HQSL[];
}
//# sourceMappingURL=hqsl.d.ts.map