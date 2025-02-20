import { parse, format } from "date-fns";
import { UTCDate } from "@date-fns/utc";
const hamTimeFormat = "yyyyMMddHHmm";
const displayTimeFormat = "yyyy-MM-dd HH:mm";
export function fromHamDate(s) {
    return parse(s + "Z", hamTimeFormat + "X", new UTCDate());
}
export function toHamDate(d) {
    return format(d, hamTimeFormat);
}
export function displayHamDate(d) {
    return format(d, displayTimeFormat);
}
export function adifDate(d) {
    return format(d, "yyyyMMdd");
}
export function adifTime(d) {
    return format(d, "HHmm");
}
//# sourceMappingURL=date.js.map