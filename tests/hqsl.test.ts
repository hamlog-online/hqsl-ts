import { HQSL } from "../src/hqsl";

import { cardFromFile, getSignedPart, slurpFileString } from "./testutils";

test("HQSL parser is reversible.", () => {
    const card = cardFromFile("normal.hqsl");

    const rawCard = getSignedPart(card);

    const hqsl = HQSL.fromString(card);
    expect(hqsl.signedData).toBe(rawCard);
});

test("HQSL parser accepts header-ed cards.", () => {
    const fullUrl = slurpFileString("normal.hqsl");

    const rawCard = getSignedPart(fullUrl.split("#")[1]);

    const hqsl = HQSL.fromString(fullUrl);
    expect(hqsl.signedData).toBe(rawCard);
});

test("Unsigned HQSL can be parsed and formatted.", () => {
    const card = cardFromFile("unsigned.hqsl");
    const rawCard = getSignedPart(card);
    const hqsl = HQSL.fromString(card);
    expect(hqsl.signedData).toBe(rawCard);

    const unparsedCard = HQSL.fromString(card).toString();
    expect(card).toBe(unparsedCard);
});

test("Known bad cards throw parse errors.", () => {
    const card = cardFromFile("parse-error.hqsl");
    expect(() => {
        HQSL.fromString(card);
    }).toThrow(SyntaxError);
});

test("HQSL cards can be formatted as ADIF.", () => {
    const card = cardFromFile("normal.hqsl");
    const hqsl = HQSL.fromString(card);
    expect(hqsl.toADIF())
        .toEqual(`Cryptographically signed QSO delivered in HQSL format
<adif_ver:5>3.1.4
<eoh>

<CALL:5>AC1PZ
<OPERATOR:5>W1KOT
<QSO_DATE:8>20240208
<TIME_ON:4>1323
<RST_RCVD:3>+00
<MODE:3>FT8
<FREQ:6>18.101
<BAND:3>17m
<QSL_RCVD:1>Y
<APP_HQSL_DATA:239>AC1PZ,FN42gv,W1KOT,202402081323,+00,18.101,FT8,59_05,,19H4V9DABY5VH3WE05MV34Z5JBEBJRD9Q7VTLB98L789GFL79P56QWFX0JHV3U6VSEXRODMYLOZ40UM798EV4FSPVY8YVMQ0WLZA66Q38VW0G6PV23O6Y65PK94NZE5B381MHOPR4NJJU67QC25JW85JL23V644BLP0HD8KBY2MODEBRICTZ5C0LC
<GRIDSQUARE:6>FN42gv
<COMMENT:5>59 05
<eor>
`);
});

test("HQSL objects can be parsed from ADIF", () => {
    const adif = slurpFileString("test.adif");
    const cards = HQSL.fromADIF(adif, "ac1pz", "FN42");
    expect(cards[0].toString()).toEqual(
        "AC1PZ,FN42gv,EA2ESK,202309241038,-06,28.075,FT8,,,UNSIGNED"
    );
});

test("SWLs can make valid HQSL cards too", () => {
    const card = HQSL.fromString(
        "R62-SWL,FN42gv,EA2ESK,202309241038,-06,28.075,FT8,AC1PZ,,UNSIGNED"
    );
    expect(card.from).toBe("R62-SWL");
    expect(card.signedData).toStrictEqual(
        "R62-SWL,FN42gv,EA2ESK,202309241038,-06,28.075,FT8,AC1PZ,"
    );
});

test("Cards with empty location field are handled correctly", () => {
    const raw = "AC1PZ,,EA2ESK,202309241038,-06,28.075,FT8,,";
    const example = raw + ",UNSIGNED";
    const adif = slurpFileString("test.adif");
    const cards = HQSL.fromADIF(adif, "ac1pz", "FN42");
    const card = cards[0];
    card.where = "";
    expect(card.toString()).toEqual(example);
    const reversed = HQSL.fromString(example);
    expect(reversed.toString()).toEqual(card.toString());
    expect(reversed.signedData).toBe(raw);
});
