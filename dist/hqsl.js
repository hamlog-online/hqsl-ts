import { AdifFormatter, AdifParser } from "adif-parser-ts";
import { fromHamDate, toHamDate, displayHamDate, adifDate, adifTime, } from "./util/date";
import { normalizeFreq, freqBand, bandFreqMode } from "./util/frequency";
import { encoder, alphabetRe } from "./util/sigencoder";
const fieldSeparator = ",";
export const callsignRe = /^[A-Z0-9/-]+$/g;
export const gridRe = /^[A-Ra-r]{2}[0-9]{2}([A-Xa-x]{2})*([0-9]{2})*([A-Xa-x]{2})*$/;
export const cardRe = /^[0-9A-Za-z?:@._~!$&'()*+;=,\-\/]+$/g;
const pseudoSigStr = "UNSIGNED";
export class HQSL {
    constructor(fields) {
        if (fields !== undefined) {
            return Object.assign(this, fields);
        }
        return this;
    }
    static fromString(s) {
        if (!s) {
            throw SyntaxError("Empty string");
        }
        const src = s.split("#").pop();
        if (!src || !src.match(cardRe)) {
            throw new SyntaxError("Wrong characters in HQSL text");
        }
        const fields = src.split(fieldSeparator);
        if (fields.length != 10) {
            throw new SyntaxError("Incorrect number of fields");
        }
        const hFrom = fields[0];
        const hTo = fields[2];
        if (!hFrom.match(callsignRe) || !hTo.match(callsignRe)) {
            throw new SyntaxError("Malformed callsign");
        }
        const hWhere = fields[1];
        if (hWhere !== "") {
            if (!hWhere.match(gridRe) ||
                hWhere.length < 4 ||
                hWhere.length % 2 > 0) {
                throw new SyntaxError("Malformed grid square");
            }
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
        const hSig = fields[9] == pseudoSigStr ? null : encoder.decode(fields[9]);
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
    get band() {
        return this.freq ? freqBand(this.freq) : "";
    }
    get hamDate() {
        return this.when ? toHamDate(this.when) : "";
    }
    get displayDate() {
        return this.when ? displayHamDate(this.when) : "";
    }
    get signedData() {
        var _a, _b, _c, _d;
        for (const field of ["from", "to", "when", "mode", "freq"]) {
            if (!this[field]) {
                throw new SyntaxError("Missing required field: " + field);
            }
        }
        if (!((_a = this.from) === null || _a === void 0 ? void 0 : _a.match(callsignRe)) ||
            !((_b = this.to) === null || _b === void 0 ? void 0 : _b.match(callsignRe)) ||
            !(this.where === "" || ((_c = this.where) === null || _c === void 0 ? void 0 : _c.match(gridRe))) ||
            !((_d = this.mode) === null || _d === void 0 ? void 0 : _d.match(cardRe)) ||
            !this.when ||
            !this.freq ||
            !(this.extra || "+").match(cardRe) ||
            !(this.signal || "+").match(cardRe) ||
            !(this.reserved || "+").match(cardRe)) {
            throw new SyntaxError("Incomplete or malformed HQSL cannot be signed.");
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
    toString() {
        return (this.signedData +
            fieldSeparator +
            (this.signature
                ? encoder.encode(this.signature || [])
                : pseudoSigStr));
    }
    toADIF() {
        const record = {
            CALL: this.from,
            OPERATOR: this.to,
            QSO_DATE: adifDate(this.when),
            TIME_ON: adifTime(this.when),
            RST_RCVD: this.signal,
            MODE: this.mode,
            FREQ: this.freq,
            BAND: this.band,
            QSL_RCVD: "Y",
            APP_HQSL_DATA: this.toString(),
        };
        if (this.where && this.where !== "") {
            record["GRIDSQUARE"] = this.where.slice(0, 8);
            if (this.where.length > 8) {
                record["GRIDSQUARE_EXT"] = this.where.slice(8, 12);
            }
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
    static fromADIF(s, call, grid) {
        const adif = AdifParser.parseAdi(s);
        const result = [];
        for (const record of adif.records || []) {
            result.push(Object.assign(new HQSL(), {
                from: record.operator || record.station_callsign || call,
                where: (record.my_gridsquare || "") +
                    (record.my_gridsquare_ext || "") || grid,
                to: record.call,
                when: fromHamDate(record.qso_date + (record.time_on || "0000")),
                signal: record.rst_sent,
                freq: parseFloat(record.freq) ||
                    bandFreqMode(record.band, record.mode) ||
                    0,
                mode: record.mode,
                extra: record.comment,
            }));
        }
        return result;
    }
}
//# sourceMappingURL=hqsl.js.map