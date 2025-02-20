import { PrivateKey, readPrivateKey, readKey } from "openpgp";

import {
    HQSL,
    HQSLOpenPGP,
    HQSLState,
    addUserID,
    callID,
    generateSignerKey,
    listCalls,
} from "../src/index";
import { cardFromFile, slurpFileString, slurpFileBuffer } from "./testutils";
import { UTCDate } from "@date-fns/utc";

// Using two merged keys to simulate the case of the keyserver returning multiple keys
// from a lookup.
const mergedKey = slurpFileString("merged.asc");

const unsignedKey = slurpFileString("ac1pz_unsigned.asc");
const signedKey = slurpFileString("ac1pz_signed.asc");
const revokedKey = slurpFileString("ac1pz_revoked.asc");
const recertifiedKey = slurpFileString("ac1pz_recertified.asc");
const certifierKeys = [slurpFileString("hqsl.asc")];
const mockKeyservers = ["http://localhost"];

let client: HQSLOpenPGP;
let signingKey: PrivateKey;
let signingDate: Date;
let qsoDate: Date;

beforeAll(async () => {
    client = await HQSLOpenPGP.setup(certifierKeys, mockKeyservers);

    signingKey = await readPrivateKey({
        binaryKey: slurpFileBuffer("ac1pz.key"),
    });

    // For experimental consistency we're going to use a stable signing date:
    // key creation + 1 minute.
    signingDate = new Date(
        new Date().setTime(signingKey.getCreationTime().getTime() + 60 * 1000)
    );

    // Similar for QSO date, but a few more minutes..
    qsoDate = new Date(
        new Date().setTime(
            signingKey.getCreationTime().getTime() + 60 * 1000 * 30
        )
    );
});

test("HQSLOpenPGP properly processes keyserver URLs.", async () => {
    const client = await HQSLOpenPGP.setup(
        [],
        [
            "hkp://localhost/",
            "hkps://localhost",
            "https://localhost",
            "hkp://localhost:1234",
        ]
    );

    expect(client.keyServers).toStrictEqual([
        "http://localhost:11371/",
        "https://localhost/",
        "https://localhost/",
        "http://localhost:1234/",
    ]);
});

test("Known good HQSL is fully verified.", async () => {
    fetchMock.mockOnce(mergedKey);
    const hqsl = HQSL.fromString(cardFromFile("normal.hqsl"));
    await client.verify(hqsl);
    expect(hqsl.verification?.verdict).toBe(HQSLState.Valid);
});

test("Known good HQSL checked against uncertified key is uncertified.", async () => {
    fetchMock.mockOnce(unsignedKey);
    const hqsl = HQSL.fromString(cardFromFile("normal.hqsl"));
    await client.verify(hqsl);
    expect(hqsl.verification?.verdict).toBe(HQSLState.KeyNotCertified);
});

test("Known bad QSL says the signature is invalid.", async () => {
    fetchMock.mockOnce(mergedKey);
    const hqsl = HQSL.fromString(cardFromFile("broken.hqsl"));
    await client.verify(hqsl);
    expect(hqsl.verification?.verdict).toBe(HQSLState.Invalid);
});

test("HQSL can be built from scratch, signed and verified.", async () => {
    fetchMock.mockOnce(mergedKey);
    const card = new HQSL({
        from: "AC1PZ",
        to: "W1KOT",
        freq: 14.074,
        where: "FN42",
        signal: "+00",
        mode: "FT8",
        when: new UTCDate(qsoDate),
    });

    // Empty mode should trip the syntax check.
    card.mode = "";
    expect(() => {
        card.signedData;
    }).toThrow(SyntaxError);
    card.mode = "FT8";

    // Use of a space in a field should trip the syntax check too.
    card.extra = " ";

    expect(() => {
        card.signedData;
    }).toThrow(SyntaxError);

    card.extra = "";

    // Before signing, verification should return a not signed verdict.
    await client.verify(card);
    expect(card.verification?.verdict).toBe(HQSLState.NotSigned);

    const signedCard = await client.sign(card, signingKey, "", signingDate);

    // eddsa signatures are deterministic, so we can expect the result to match.
    const signedCardString = signedCard.toString();
    expect(signedCardString).toBe(
        [
            "AC1PZ,FN42,W1KOT,202402081023,+00,14.074,FT8,,,",
            "19H4V9DABY5VH3WE05MV34Z5JBEBJRD9Q7VTLB98L789GFL",
            "79P56QWFX0JHV3U6VSEXRODMYLOZ40T559YAE7REKVQGE8N",
            "41DC3OLWF2O143WBYVIRRW9TAL4J7EPVQAJOQ7H8G7L66P0",
            "3F7MCOO2H0SZP1V4UO7LPWU0NWGHRUQH8AEX8AHXYEIR",
        ].join("")
    );

    await client.verify(signedCard);
    expect(signedCard.verification?.verdict).toBe(HQSLState.Valid);

    // And a torture test.
    const damagedCardString = signedCardString.replace("XYEIR", "FOOBAR");
    const damagedCard = HQSL.fromString(damagedCardString);
    await client.verify(damagedCard);
    expect(damagedCard.verification?.verdict).toBe(HQSLState.Invalid);

    // Adding extra bytes after the end should also result in a damaged signature.
    const bloatedCard =
        (await client.sign(card, signingKey, "", signingDate)).toString() +
        "FOOBAR";
    const bloatedHQSL = HQSL.fromString(bloatedCard);
    await client.verify(bloatedHQSL);
    expect(bloatedHQSL.verification?.verdict).toBe(HQSLState.Invalid);
});

test("Keys return a correct list of certifications.", async () => {
    const certifications = await client.getCertifications(
        await readKey({ armoredKey: signedKey })
    );
    expect(certifications.length).toBe(1);
    expect(certifications[0].call).toEqual("AC1PZ");
    expect(certifications[0].start.toISOString()).toEqual(
        "2023-09-18T19:00:00.000Z"
    );
    expect(certifications[0].end.toISOString()).toEqual(
        "2030-09-18T19:00:00.000Z"
    );
    expect(certifications[0].key.getFingerprint()).toEqual(
        "b54896b58145ca2d403d728c260e46861c7ce4c6"
    );
});

test("Signatures made by <call> on cards with calls with extra /-prefixes or suffixes can be verified.", async () => {
    fetchMock.mockOnce(mergedKey);
    const card = new HQSL({
        from: "AC1PZ/P",
        to: "W1KOT",
        freq: 14.074,
        where: "FN42",
        signal: "+00",
        mode: "FT8",
        when: new UTCDate(qsoDate),
    });

    const signedCard = await client.sign(card, signingKey, "", signingDate);
    await client.verify(signedCard);
    expect(signedCard.verification?.verdict).toBe(HQSLState.Valid);
});

test("Certification-revoked signer keys are considered uncertified.", async () => {
    fetchMock.mockOnce(revokedKey);
    const hqsl = HQSL.fromString(cardFromFile("normal.hqsl"));
    await client.verify(hqsl);
    expect(hqsl.verification?.verdict).toBe(HQSLState.KeyNotCertified);
});

test("Re-certified signer keys are considered uncertified.", async () => {
    // Yes, this is apparently to openpgp spec.
    fetchMock.mockOnce(recertifiedKey);
    const hqsl = HQSL.fromString(cardFromFile("normal.hqsl"));
    await client.verify(hqsl);
    expect(hqsl.verification?.verdict).toBe(HQSLState.KeyNotCertified);
});

test("Keys are generated in the expected format, new userIDs can be added.", async () => {
    // We're not accepting callsigns which won't parse later.
    expect(() => {
        callID("ac1pz");
    }).toThrow("Malformed callsign");

    const { privateKey, publicKey, revocationCertificate } =
        await generateSignerKey("Random Test User", ["AC1PZ", "AC-1234"]);

    // listCalls reports calls in alphabetical order.
    expect(listCalls(privateKey)).toStrictEqual(["AC-1234", "AC1PZ"]);

    const privateKeyReclaimed = await addUserID(privateKey, "N0CALL");
    expect(listCalls(privateKeyReclaimed)).toStrictEqual([
        "AC-1234",
        "AC1PZ",
        "N0CALL",
    ]);

    // Double check: Is it a v4 key?
    expect(privateKeyReclaimed.keyPacket.version).toBe(4);

    // Double check: Does it have the expected curve?
    const algo = privateKeyReclaimed.getAlgorithmInfo();
    expect(algo).toStrictEqual({
        algorithm: "eddsaLegacy",
        curve: "ed25519Legacy",
    });

    // Do any of the userids expire? They shouldn't.
    for (const user of privateKeyReclaimed.users) {
        const expiration = await privateKeyReclaimed.getExpirationTime(
            user.userID!
        );
        expect(expiration).toBe(Infinity);
    }
});
