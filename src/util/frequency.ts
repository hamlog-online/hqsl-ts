import { bandmap } from "./bandmap";
import { bandModeMap } from "./bandmodemap";

interface BandList {
    [key: string]: number;
}

interface BandModeList {
    [t: string]: {
        [key: string]: number;
    };
}

/**
 * Convert frequency to band name.
 * @param f Frequency in MHz
 * @returns Name of the band
 */
export function freqBand(f: number): string {
    let distance = Infinity;
    let knownBand = "??";
    for (const [band, midpoint] of Object.entries(bandmap)) {
        const newDistance = Math.abs(f - (midpoint as number));
        if (newDistance < distance) {
            distance = newDistance;
            knownBand = band;
        }
    }
    return knownBand;
}

/**
 * Convert band name to frequency. Only use in case where frequency is not known.
 * Returns null if there is no band name match. Upper and lower case are ignored.
 *
 * @param s Band name as per ADIF
 * @returns Medium frequency of the band.
 */
export function bandFreq(s: string): number | null {
    return (bandmap as BandList)[s.toLowerCase()] || null;
}

/**
 * Convert band name to frequency, mode dependent. Uses a table of defaults that
 * depends on the mode, falls back to bare band if none of the defaults match.
 *
 * @param s Band name as per ADIF
 * @param m Mode.
 * @returns Frequency somewhere in the appropriate band segment.
 */
export function bandFreqMode(s: string, m: string): number | null {
    // If the mode is an empty string, make no assumptions and just use the band default.
    if (!m) {
        return bandFreq(s);
    }
    // Determine which table of defaults to use.
    // The default table is DIGI, because a lot more modes are DIGI than any other kind.
    let table = "DIGI";
    if (["USB", "LSB", "SSB", "FM", "AM", "VOICE"].includes(m.toUpperCase())) {
        table = "PHONE";
    }
    if (["CW", "PCW"].includes(m.toUpperCase())) {
        table = "CW";
    }
    // Then look up the table, and if it comes up empty, fall back to band edges calculation.
    const tableValue = (bandModeMap as BandModeList)[table][s.toLowerCase()];
    return tableValue || bandFreq(s);
}

/**
 * Normalize frequency according to HQSL standard
 * @param n
 * @returns string representation
 * @throws {RangeError} in case of a NaN frequency.
 */

export function normalizeFreq(n: number): string {
    /*
    The frequency MUST be given in megahertz and written in a normalized form:

    1. Decimal point (`.`, `0x2E`) is used as the decimal separator.
    2. Frequencies above 1 MHz are given to a precision of no more than 3 digits 
       after the decimal.
    3. Trailing and leading zeroes are omitted. In the particular case of 
       sub-1MHz frequencies, this means that the frequency will start with 
       a decimal point.
    4. Trailing decimal point MUST be removed.
    */

    // First, error out on a NaN.
    if (isNaN(n)) {
        throw new RangeError("Bogus frequency");
    }

    // So start by converting the number to string
    // and recovering the whole and the fractional parts.
    const textual = n.toString();
    const numWhole = Math.trunc(n);
    let [whole, fractional] = textual.split(".");

    // If fractional part was undefined, make it empty.
    if (fractional === undefined) {
        fractional = "";
    }

    // If we have digits after the decimal at all and whole is >1,
    // truncate the digits.
    if (numWhole > 1) {
        fractional = fractional.slice(0, 3);
    }

    // Trim zeroes off the tail end of fractional part.
    if (fractional) {
        fractional = fractional.replace(/(0\s*$)/g, "");
    }

    // If whole part is 0, make it empty.
    if (whole == "0") {
        whole = "";
    }

    let result = `${whole}.${fractional}`;

    // If we have a trailing decimal point, remove it.
    result = result.replace(/(\.\s*$)/g, "");

    return result;
}
