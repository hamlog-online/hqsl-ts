import {
    bandFreq,
    bandFreqMode,
    freqBand,
    normalizeFreq,
} from "../src/util/frequency";

test("Band mapper behaves as designed", () => {
    expect(freqBand(0.136)).toBe("2190m");
    expect(freqBand(0.473)).toBe("630m");
    expect(freqBand(1.9)).toBe("160m");
    expect(freqBand(3.6)).toBe("80m");
    expect(freqBand(5.4)).toBe("60m");
    expect(freqBand(7.074)).toBe("40m");
    expect(freqBand(10.12)).toBe("30m");
    expect(freqBand(14.074)).toBe("20m");
    expect(freqBand(18.1)).toBe("17m");
    expect(freqBand(21.3)).toBe("15m");
    expect(freqBand(24.9)).toBe("12m");
    expect(freqBand(28.5)).toBe("10m");
    expect(freqBand(41)).toBe("8m");
    expect(freqBand(52)).toBe("6m");
    expect(freqBand(70.25)).toBe("4m");
    expect(freqBand(145)).toBe("2m");
    expect(freqBand(220)).toBe("1.25m");
    expect(freqBand(433)).toBe("70cm");
    expect(freqBand(910)).toBe("33cm");
    expect(freqBand(1250)).toBe("23cm");
    expect(freqBand(2400)).toBe("13cm");
    expect(freqBand(3400)).toBe("9cm");
    expect(freqBand(5700)).toBe("6cm");
    expect(freqBand(10200)).toBe("3cm");
    expect(freqBand(24100)).toBe("1.25cm");
    expect(freqBand(47100)).toBe("6mm");
    expect(freqBand(77000)).toBe("4mm");
});

test("Frequency normalizer working as specified.", () => {
    expect(normalizeFreq(18.1045)).toBe("18.104");
    expect(normalizeFreq(0.001358)).toBe(".001358");
    expect(normalizeFreq(18.0)).toBe("18");
    expect(() => {
        normalizeFreq(NaN);
    }).toThrow(RangeError);
});

test("Band to frequency works as designed.", () => {
    expect(bandFreq("20M")).toBe(14.175);
    expect(bandFreq("bogus")).toBe(null);
});

test("Band to frequency with mode assumptions works as designed.", () => {
    expect(bandFreqMode("20M", "cw")).toBe(14.02);
    expect(bandFreqMode("20M", "usb")).toBe(14.22);
    expect(bandFreqMode("20M", "newfangled")).toBe(14.07);
    // Mode-dependent table doesn't go this far up, so this should result
    // in edge-calculated default, but not null.
    expect(bandFreqMode("1mm", "cw")).toBe(245500);
    expect(bandFreqMode("bogus", "cw")).toBe(null);
});
