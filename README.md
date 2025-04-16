# HQSL parser and verifier in TypeScript

See [HQSL.net](https://hqsl.net/) for detailed information on what an HQSL is and why would one want to use this.

This is a TypeScript library for parsing, signing, verifying and creating HQSL cards, as used in the HQSL.net card verifier and on [Hamlog.Online](https://hamlog.online/), meant for web use, WebView-based mobile apps, and Node.js.

The library currently supports the 1.1.0 version of the HQSL standard.

## Usage

```bash
npm install hqsl-ts
```

If you're using TypeScript, you might want to use the TypeScript source code directly instead of the compiled versions:

```json
// tsconfig.json
...
    "paths": {
      "hqsl-ts": ["./node_modules/hqsl-ts/src"],
    }
...
```

Using this library without a bundler or from a CDN is not currently supported, due to the dependencies involved introducing a significant number of hoops that need jumping. *(Pull requests rectifying this situation are welcome.)* Since it is assumed you're using a bundler, no pre-minified versions are included. You can still load, e.g. `openpgpjs` from CDN, by adding it as an external dependency and using `https://cdn.jsdelivr.net/npm/openpgp@6.1.0/dist/openpgp.min.js` for the URL.

## Examples

Refer to [API documentation](https://hamlog-online.github.io/hqsl-ts/) for full details. Here are some brief examples:

### Creating a card from ADIF

```typescript
import { HQSL } from "hqsl-ts";

const adif = `
ADIF export from CQRLOG for Linux version 2.5.2, slightly edited.

<ADIF_VER:5>3.1.0
<CREATED_TIMESTAMP:15>20240416 114238
<PROGRAMID:6>CQRLOG
<PROGRAMVERSION:11>2.5.2 (001)
<EOH>
<QSO_DATE:8>20210924<TIME_ON:4>1038<TIME_OFF:4>1039<STATION_CALLSIGN:5>AC1PZ<CALL:6>EA2ESN<MODE:3>FT8<FREQ:7>28.0759<BAND:3>10M<RST_SENT:3>-06<RST_RCVD:3>-13<QSL_SENT:1>N
<QSL_RCVD:1>N<GRIDSQUARE:6>IN91dv<MY_GRIDSQUARE:6>FN42gv<TX_PWR:2>20
<EOR>`; 

// This parses the ADIF string and supplies defaults for fields not necessarily included.
const hqsl = HQSL.fromADIF(adif, "AC1PZ", "FN42");
// The result is every QSO in the ADIF string transformed into an HQSL object:
console.log(hqsl[0].toString());

```

### Creating a card from scratch and signing it

```typescript
import { HQSL, HQSLOpenPGP } from "hqsl-ts";
import { UTCDateMini } from "@date-fns/utc";

const secretKey = `
-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEZcSkgRYJKwYBBAHaRw8BAQdA2HVnF04A6dQuF2ID5hh5W7KHRCllqZQHn9kF
...
=crTM
-----END PGP PRIVATE KEY BLOCK-----`;

// Here we are creating a card by manually supplying the required data.
const card = new HQSL({
    from: "AC1PZ",
    to: "W1KOT",
    freq: 14.074,
    where: "FN42",
    signal: "+00",
    mode: "FT8",
    when: new UTCDateMini(2022, 2, 13, 16, 10),
});

(async () => {
    // This sets up the signer. Since we're not verifying anything,
    // we don't need to supply trusted certifier keys.
    const client = await HQSLOpenPGP.setup([]);
    // Actually sign the card.
    await client.sign(card, signingKey);
    // The result is a signed card body, and we point it at the HQSL.net verifier
    // by attaching the URL header.
    console.log(`https://hqsl.net/h#${card.toString()}`);

    // If you need to generate a QR code in the browser or in Node.js,
    // the recommended library is
    // tiny-qrcode-svg (https://github.com/withaspoon/tiny-qrcode-svg)
    // because it handles the optimized multi-block QR codes automatically.
})();

```

### Verifying a card

```typescript
import { HQSL, HQSLOpenPGP, HQSLState } from "hqsl-ts";

const trustedKey = `
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZbigARYJKwYBBAHaRw8BAQdAJNNtGMTfd6lLFQDhf1Rh2DDqACwQyd1VTF2R
...
=D6ih
-----END PGP PUBLIC KEY BLOCK-----
`;
const card = "https://hqsl.net/h#AC1PZ,FN42gv,W1KOT," +
             "202402081323,+00,18.101,FT8,59_05,," + 
             "19H4V9DABY5VH3WE05MV34Z5JBEBJRD9Q7V" + 
             "TLB98L789GFL79P56QWFX0JHV3U6VSEXROD" + 
             "MYLOZ40UM798EV4FSPVY8YVMQ0WLZA66Q38" + 
             "VW0G6PV23O6Y65PK94NZE5B381MHOPR4NJJ" +
             "U67QC25JW85JL23V644BLP0HD8KBY2MODEBRICTZ5C0LC";

(async () => {
    // This gets you a parsed card object.
    const hqsl = HQSL.fromString(card);

    // At this point, you can already access properties on the object, if it got parsed correctly.
    // If it didn't, the fromString method will throw an error.
    
    // This sets up the verifier and feeds it the certifier key we trust.
    const client = await HQSLOpenPGP.setup([trustedKey]);

    // This actually adds the verification verdict to the card object.
    await client.verify(hqsl);

    // If the card is completely legit, this will print 'true'!
    console.log(hqsl.verification.verdict == HQSLState.Valid)

})();
```

## Tooling

+ `npm run build` to build for consumption. This will also build API documentation.
+ `npm run test` to run unit tests.
+ `npm run doc` to generate API documentation.

## Upgrading to 2.0

There are two sets of changes that might require your attention if you were using hqsl-ts:

1. hqsl-ts switched to using to OpenPGPjs version 6. That required certain changes in the internals which will probably make hqsl-ts break when used with earlier versions, which is important if you were using OpenPGPjs from CDN.
2. hqsl-ts switched to using `date-fns` version 4, which introduces significant changes in timezone support. This means that it now must use `UTCDate` rather than `UTCDateMini` everywhere.

Otherwise, the only noteworthy change is the addition of functions to aid you in generating known-suitable signer keys and add User IDs to them.

## License

This library is released under the terms of MIT license. See [LICENSE](LICENSE).
