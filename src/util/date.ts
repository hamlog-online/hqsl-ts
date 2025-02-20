import { parse, format } from "date-fns";
import { UTCDate } from "@date-fns/utc";

const hamTimeFormat = "yyyyMMddHHmm";
const displayTimeFormat = "yyyy-MM-dd HH:mm";

/**
 * Parse an UTC datetime from the HQSL standard format.
 *
 * @param s string
 * @returns Date in UTC
 */
export function fromHamDate(s: string): UTCDate {
    return parse(s + "Z", hamTimeFormat + "X", new UTCDate());
}

/**
 * Convert a datetime to HQSL standard format.
 *
 * @param d Date to convert
 * @returns A datetime string.
 */
export function toHamDate(d: Date): string {
    return format(d, hamTimeFormat);
}

/**
 * Format an UTC date into a generic display format.
 *
 * @param d Date to display
 * @returns
 */
export function displayHamDate(d: Date): string {
    return format(d, displayTimeFormat);
}

/**
 * Format an UTC date for ADIF QSO_DATE field.
 *
 * @param d Date to format
 * @returns
 */
export function adifDate(d: Date): string {
    return format(d, "yyyyMMdd");
}

/**
 * Format an UTC date for ADIF TIME_ON field.
 *
 * @param d Date to format
 * @returns
 */
export function adifTime(d: Date): string {
    return format(d, "HHmm");
}
