/*

HQSL class takes care of parsing an HQSL from string or ADIF, and packaging it
to a string or ADIF, creating it from objects and sanity checking.

*/

import { AdifFormatter, AdifParser } from "adif-parser-ts";
import type { UTCDate } from "@date-fns/utc";

import type { HQSLVerification } from "./hqsl-verification";

import {
    fromHamDate,
    toHamDate,
    displayHamDate,
    adifDate,
    adifTime,
} from "./util/date";
import { normalizeFreq, freqBand, bandFreqMode } from "./util/frequency";
import { encoder, alphabetRe } from "./util/sigencoder";

// Some format globals.
const fieldSeparator = ",";

/** Regular expression that matches callsigns and nothing else. */
export const callsignRe = /^[A-Z0-9/-]+$/g;

/** Regular expression that matches grid squares. Not perfect. */
export const gridRe =
    /^[A-Ra-r]{2}[0-9]{2}([A-Xa-x]{2})*([0-9]{2})*([A-Xa-x]{2})*$/;

/** Regular expression that matches characters valid within the card text.
 * See https://stackoverflow.com/a/26119120 for the logic on how it was derived.
 */
export const cardRe = /^[0-9A-Za-z?:@._~!$&'()*+;=,\-\/]+$/g;

// An unsigned card has to have a special string in its signature field:
const pseudoSigStr = "UNSIGNED";

/**
 * The HQSL object represents a QSO through the entire parsing, signing and verification life cycle.
 */
export class HQSL {
    /** Sender's call sign */
    from?: string;
    /** Sender's grid square */
    where?: string;
    /** Correspondent's call sign. */
    to?: string;
    /** QSO date in UTC. Requires the use of date-fns to properly work in UTC. */
    when?: UTCDate;
    /** Signal report. */
    signal?: string;
    /** Frequency. */
    freq?: number;
    /** Mode. */
    mode?: string;
    /** Extra data. */
    extra?: string;
    /** Reserved field. Don't use it. */
    reserved?: string;
    /** Binary signature data. */
    signature?: Uint8Array;
    /** Verification results. */
    verification?: HQSLVerification;

    /** Construct a HQSL from scratch.
     *
     * No syntax checking is performed at this stage, though it will happen when anything calls {@link signedData}.
     */
    constructor(fields?: {
        /** QSL sender call sign. */
        from: string;
        /** QSL sender Maidenhead grid location. */
        where: string;
        /** QSL recipient call sign. */
        to: string;
        /** QSO datetime in UTC. */
        when: UTCDate;
        /** Signal report. */
        signal?: string;
        /** Frequency in MHz. */
        freq: number;
        /** Communication mode. */
        mode: string;
        /** Extra data. */
        extra?: string;
    }) {
        if (fields !== undefined) {
            return Object.assign(this, fields);
        }
        return this;
    }

    /**
     * Parses a HQSL from string, applying as many verification checks as feasible.
     * Will ignore an URL header if present.
     *
     * @param s A string containing the HQSL
     * @returns HQSL object
     * @throws `SyntaxError` describing a particular parsing error.
     */
    static fromString(s: string): HQSL {
        // Sanity checking
        if (!s) {
            throw SyntaxError("Empty string");
        }

        // Split off the header in case it made it here.
        const src = s!.split("#").pop();

        if (!src || !src.match(cardRe)) {
            throw new SyntaxError("Wrong characters in HQSL text");
        }

        const fields = src.split(fieldSeparator);

        // If we don't have exactly 10 fields, abort.
        if (fields.length != 10) {
            throw new SyntaxError("Incorrect number of fields");
        }

        const hFrom = fields[0];
        const hTo = fields[2];

        if (!hFrom.match(callsignRe) || !hTo.match(callsignRe)) {
            throw new SyntaxError("Malformed callsign");
        }

        const hWhere = fields[1];

        if (
            !hWhere.match(gridRe) ||
            hWhere.length < 4 ||
            hWhere.length % 2 > 0
        ) {
            throw new SyntaxError("Malformed grid square");
        }

        const hWhen = fromHamDate(fields[3]);
        if (isNaN(hWhen.getTime())) {
            throw new SyntaxError("Malformed datetime");
        }
        const hSignal = fields[4];

        const hFreq = parseFloat(fields[5]);
        if (isNaN(hFreq)) {
            throw new SyntaxError("Malformed frequency");
        }

        const hMode = fields[6];
        const hExtra = fields[7];

        if (!!fields[9] && !fields[9].match(alphabetRe)) {
            throw new SyntaxError("Malformed signature");
        }

        // If that throws an error, that should bubble up.
        const hSig =
            fields[9] == pseudoSigStr
                ? null
                : encoder.decode(fields[9]);

        return Object.assign(new HQSL(), {
            from: hFrom,
            where: hWhere,
            to: hTo,
            when: hWhen,
            signal: hSignal,
            freq: hFreq,
            mode: hMode,
            extra: hExtra,
            reserved: fields[8],
            signature: hSig,
        });
    }

    /**
     * Derives an ADIF-standardized band name from frequency.
     */
    get band(): string {
        return this.freq ? freqBand(this.freq) : "";
    }

    /**
     * Derives a datetime formatted as per HQSL standard.
     */
    get hamDate(): string {
        return this.when ? toHamDate(this.when) : "";
    }

    /**
     * Derives a date in a generic ISO-like format for display.
     */
    get displayDate(): string {
        return this.when ? displayHamDate(this.when) : "";
    }

    /**
     * Constructs a signable string from the HQSL, throwing SyntaxErrors in case of missing
     * or malformed data fields.
     *
     * @returns The entire HQSL as string sans the signature field.
     */
    get signedData(): string {
        for (const field of ["from", "to", "where", "when", "mode", "freq"]) {
            if (!this[field as keyof HQSL]) {
                throw new SyntaxError("Missing required field: " + field);
            }
        }

        if (
            !this.from?.match(callsignRe) ||
            !this.to?.match(callsignRe) ||
            !this.where?.match(gridRe) ||
            !this.mode?.match(cardRe) ||
            !this.when ||
            !this.freq ||
            // These three fields are allowed to be empty,
            // but if they aren't empty, they also must
            // fit the fragment-allowed characters restriction.
            !(this.extra || "+").match(cardRe) ||
            !(this.signal || "+").match(cardRe) ||
            !(this.reserved || "+").match(cardRe)
        ) {
            throw new SyntaxError(
                "Incomplete or malformed HQSL cannot be signed."
            );
        }

        return [
            this.from,
            this.where,
            this.to,
            this.hamDate,
            this.signal || "",
            normalizeFreq(this.freq),
            this.mode,
            this.extra || "",
            this.reserved || "",
        ].join(fieldSeparator);
    }

    /**
     * Formats a complete HQSL as string. Signed HQSLs will
     * contain the encoded signature, while unsigned will
     * have UNSIGNED in the signature field as the standard specifies.
     *
     * @returns A string containing the HQSL (sans a header)
     */
    toString(): string {
        return (
            this.signedData +
            fieldSeparator +
            (this.signature
                ? encoder.encode(this.signature || [])
                : pseudoSigStr)
        );
    }

    /**
     * Formats a complete HQSL as an ADIF string.
     * Will contain a fully encoded .toString() in APP_HQSL_DATA.
     *
     * @returns A string of a single-QSO ADIF.
     */
    toADIF(): string {
        const record: any = {
            CALL: this.from as string,
            OPERATOR: this.to as string,
            QSO_DATE: adifDate(this.when as UTCDate),
            TIME_ON: adifTime(this.when as UTCDate),
            GRIDSQUARE: (this.where as string).slice(0, 8),
            RST_RCVD: this.signal,
            MODE: this.mode, // TODO: We need to massage it back to adif, don't we.
            FREQ: this.freq,
            BAND: this.band,
            QSL_RCVD: "Y",
            APP_HQSL_DATA: this.toString(),
        };
        if (this.where && this.where.length > 8) {
            record["GRIDSQUARE_EXT"] = (this.where as string).slice(8, 12);
        }
        if (this.extra) {
            record["COMMENT"] = this.extra.replace("_", " ");
        }

        return AdifFormatter.formatAdi({
            header: {
                text: "Cryptographically signed QSO delivered in HQSL format",
                adif_ver: "3.1.4",
            },
            records: [record],
        });
    }

    /**
     * Parses an ADIF file string to construct a series of HQSL.
     * Whether any of it will be signable
     * depends on how complete the ADIF was.
     *
     * @param s An ADIF file string.
     * @param call The default call to assume if none is present in the record.
     * @param grid The default grid to assume if none is present in the record.
     * @throws `Error` in case of ADIF parsing errors and `SyntaxError`
     * when data of a QSO is insufficient to construct a valid HQSL.
     */
    static fromADIF(s: string, call: string, grid: string): HQSL[] {
        const adif = AdifParser.parseAdi(s);
        const result: HQSL[] = [];
        for (const record of adif.records || []) {
            result.push(
                Object.assign(new HQSL(), {
                    from: record.operator || record.station_callsign || call,
                    where:
                        record.my_gridsquare +
                            (record.my_gridsquare_ext || "") || grid,
                    to: record.call,
                    when: fromHamDate(
                        record.qso_date + (record.time_on || "0000")
                    ),
                    signal: record.rst_sent,
                    freq: parseFloat(record.freq) || bandFreqMode(record.band, record.mode) || 0,
                    mode: record.mode,
                    extra: record.comment,
                })
            );
        }
        return result;
    }
}
