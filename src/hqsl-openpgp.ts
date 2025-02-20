/*

HQSLOpenPGP takes care of signing an HQSL object and verifying it, given keys and keyservers.

Module consumers can, theoretically, import them separately.

*/

// openpgp.d.ts is missing few things and we declare them ourselves.
/// <reference path='./openpgp-missing.d.ts' />

import type { UTCDate } from "@date-fns/utc";
import {
    PublicKey,
    PrivateKey,
    Signature,
    readKeys,
    readSignature,
    createMessage,
    verify,
    sign,
    decryptKey,
    generateKey,
    reformatKey,
} from "openpgp";
import { isAfter, isBefore } from "date-fns";

import { callsignRe, HQSL } from "./hqsl";
import { HQSLState } from "./hqsl-verification";
import { Uint8ArrayToHex, fetchWithTimeout } from "./util/misc";
import { fromHamDate } from "./util/date";

// Note the `-`: SWLs also send HQSL.
const uidRe = /^Amateur Radio Callsign: ([0-9A-Z-]+)$/g;

const notationName = "qsl@hqsl.net";

/**
 * Describes a timespan which a certain public key is entitled to use
 * for certifying a QSO, as certified by trusted keys. This is the type
 * of the return value of getCertifications method.
 */
export type CertificationRange = {
    /** Callsign, with no prefixes or suffixes */
    call: string;
    /** Start time in UTC */
    start: UTCDate;
    /** End time in UTC */
    end: UTCDate;
    /** The public key object that certified this particular time range. */
    key: PublicKey;
};

/**
 * Fetch doesn't recognize hkp and hkps URL schemes.
 * So we need to transform hkp to http://<domain>:11371
 * (unless there's a port in there already, in which case it stays)
 * and hkps://<domain> to https.
 *
 * @param url Url to transform
 */
function normalizeUrl(url: string): string {
    // Fun fact: You're not allowed to freely swap protocols in an URL.
    // Which is insane, but whatever.
    let newUrl = new URL(url);
    let result = newUrl.href;
    if (newUrl.protocol == "hkps:") {
        newUrl.protocol = "https";
        result = newUrl.href.replace(/^hkps:/, "https:");
    } else if (newUrl.protocol == "hkp:") {
        newUrl.protocol = "http";
        newUrl.port = newUrl.port || "11371";
        result = newUrl.href.replace(/^hkp:/, "http:");
    }
    if (!result.endsWith("/")) {
        result += "/";
    }
    return result;
}

/**
 * A verifier and signer class for HQSL, this object takes
 * care of interfacing to key servers
 * and working with public keys.
 */
export class HQSLOpenPGP {
    /** Array of public keys to be trusted for certification. */
    trustedKeys: PublicKey[];
    /** List of key server URLs. */
    keyServers: string[] = [];
    /** Timeout used when accessing key servers. */
    timeout: number;

    /**
     * You will generally want to use {@link setup} instead.
     */
    constructor(
        /** Array of public key objects to trust. */
        trustedKeys: PublicKey[],
        /** Array of key server URLs. */
        keyServers: string[],
        /** Timeout on key server lookups. */
        timeout: number
    ) {
        this.trustedKeys = trustedKeys;

        for (const url of keyServers) {
            this.keyServers.push(normalizeUrl(url));
        }

        this.timeout = timeout;
    }

    /**
     * Create a new HQSL verifier and signer instance. You have to use this,
     * instead of a straight constructor, because of the async operations involved.
     *
     * @param trustedKeys Array of certifier keys to be considered trustworthy.
     *                    Can be ascii-armored, binary, or pre-loaded OpenPGP keys.
     * @param keyServers Array of key server URLs. Key servers are assumed to be
     *                   HKPS/HKP keyservers, so nothing but the domain name and
     *                   the protocol (and optionally, port) should actually be present.
     *                   If empty or omitted, the default hqsl.net keyserver will be used.
     * @param timeout Key server request timeout. The default timeout is set at 1000ms.
     * @returns The instance you will be using.
     */
    static async setup(
        trustedKeys: Array<string | Uint8Array | PublicKey>,
        keyServers?: string[],
        timeout?: number
    ): Promise<HQSLOpenPGP> {
        let keys: PublicKey[] = [];
        for (const key of trustedKeys) {
            if (typeof key === "string") {
                keys = keys.concat(await readKeys({ armoredKeys: key }));
            } else if (key instanceof Uint8Array) {
                keys = keys.concat(await readKeys({ binaryKeys: key }));
            } else if (key instanceof PublicKey) {
                keys.push(key);
            }
        }
        return new HQSLOpenPGP(
            keys,
            keyServers && keyServers.length ? keyServers : ["https://hqsl.net"],
            timeout || 1000
        );
    }

    /**
     * Lookup a key on every HKP keyserver initialized into the instance.
     * Will stop trying them in order the moment one returns a reply
     * containing a public key.
     *
     * @param query Query string. When seeking by key IDs, you may
     *              want to add "0x" yourself, if needed.
     * @throws `Error` if no key is found.
     * @returns Parsed public keys.
     */
    async lookup(query: string): Promise<PublicKey[]> {
        for (const baseUrl of this.keyServers) {
            // Normalized baseURL includes a slash.
            let url = `${baseUrl}pks/lookup?op=get&options=mr&search=${query}`;

            try {
                const response = await fetchWithTimeout(url, {
                    timeout: this.timeout,
                });
                if (response.status === 200) {
                    const txt = await response.text();
                    if (txt.indexOf("-----END PGP PUBLIC KEY BLOCK-----") > 0) {
                        return await readKeys({
                            armoredKeys: txt,
                        });
                    }
                    console.error(
                        `Server ${baseUrl} returned something other than an OpenPGP key.`
                    );
                }
            } catch (error) {
                /* Report error and skip to the next key server: there's no
                point to use more than one key server if they aren't in a
                network, is there? */

                console.error(`Public key server ${baseUrl} timed out.`);
            }
        }
        throw new Error("Key not found");
    }

    /**
     * Verify a signed HQSL object.
     *
     * @param qsl The HQSL object to verify.
     * @returns {HQSL} object with the verification field containing verification results.
     */
    async verify(qsl: HQSL): Promise<HQSL> {
        // Yes, this can happen.
        if (qsl === undefined) {
            return qsl;
        }

        /*
        
        Sanity checks:

        A QSL that has no sender call sign or a broken qso datetime can't be
        verified. This normally can't happen unless you're trying to verify a
        qsl assembled from parts, but just in case it does...

        */
        if (!qsl.from || !qsl.when) {
            qsl.verification = { verdict: HQSLState.Invalid };
            return qsl;
        }

        /* Force clear verification results in case we're getting called
        twice, for consistency. */

        qsl.verification = undefined;

        if (!qsl.signature) {
            qsl.verification = { verdict: HQSLState.NotSigned };
            return qsl;
        }

        let sig: Signature;

        try {
            sig = await readSignature({
                binarySignature: qsl.signature,
            });
        } catch (error) {
            qsl.verification = { verdict: HQSLState.Invalid };
            return qsl;
        }

        const message = await createMessage({
            text: qsl.signedData,
            format: "binary",
        });

        /* Having a signature made by multiple issuers is not in the standard
        and not supported. */

        const signers = sig.getSigningKeyIDs();
        if (signers.length != 1) {
            qsl.verification = { verdict: HQSLState.Invalid };
            return qsl;
        }

        const signingKeyId = signers[0].toHex();

        let foundKeys: PublicKey[];
        try {
            foundKeys = await this.lookup(`0x${signingKeyId}`);
        } catch (error) {
            qsl.verification = { verdict: HQSLState.KeyNotFound };
            return qsl;
        }

        // We expect identical key IDs to exist, so loop.
        next_key: for (const signerKey of foundKeys) {
            const verificationResult = await verify({
                message: message,
                signature: sig,
                verificationKeys: signerKey,
                format: "binary",
            });

            for (const check of verificationResult.signatures) {
                try {
                    await check.verified; // throws on invalid signature
                    break;
                } catch (e) {
                    // If this key failed, try next key.
                    continue next_key;
                }
            }

            /* It's hard to tell which is the prefix and which is the suffix
            and which is the call itself. So we split the call in the QSO by
            '/' and check each token against the certified time ranges, since
            only the real calls will be certified anyway: */

            const chunks = qsl.from?.split("/") || [];

            const matchingRanges = (
                await this.getCertifications(signerKey)
            ).filter((x) => chunks.includes(x.call));

            /* Now we just go through the ranges we know are certified and see
            if the QSO falls into one. */

            for (const range of matchingRanges) {
                if (
                    isAfter(qsl.when, range.start) &&
                    isBefore(qsl.when, range.end)
                ) {
                    qsl.verification = {
                        verdict: HQSLState.Valid,
                        signerKey: signerKey,
                        certifierKey: range.key,
                    };
                    return qsl;
                }
            }

            // None of the ranges matched,
            // which means the key is not certified for this QSO.
            qsl.verification = {
                verdict: HQSLState.KeyNotCertified,
                signerKey: signerKey,
            };
            return qsl;
        }

        // None of the keys returned from the server could verify the signature.
        qsl.verification = { verdict: HQSLState.Invalid };
        return qsl;
    }

    /**
     * Given a public key, identify a list of callsign/start/end triplets it is
     * to be accepted for, and which key certified each triplet as such. While this is used
     * internally when verifying, it is also useful when you wish to verify an
     * arbitrary message signed by a HQSL signing key.
     *
     * @param key Public key
     * @returns An array of CertificationRange in a promise.
     */
    async getCertifications(key: PublicKey): Promise<CertificationRange[]> {
        const results: CertificationRange[] = [];

        // Revoked keys can't be certified.
        try {
            await key.verifyPrimaryKey();
        } catch (e) {
            return results;
        }

        /* This will cache verification results, but we need more detail than
        it returns. */
        await key.verifyAllUsers(this.trustedKeys);

        // Only consider correct userIDs.
        for (const uid of key.users.filter(
            (x) => x.userID && x.userID.userID.match(uidRe)
        )) {
            const call = uid.userID?.userID.replace(uidRe, "$1");

            // Skip userids which aren't self-signed.
            try {
                await uid.verify();
            } catch (e) {
                continue;
            }

            // Go through trusted keys to identify which key that was.
            next_trusted_key: for (const trustedKey of this.trustedKeys) {
                const fingerprint = trustedKey?.getFingerprint();

                let relevantSignature = -1;
                let latestTime = new Date(1970);

                // Find the latest signature that matters to acquire our notation.
                for (const [index, cert] of uid.otherCertifications.entries()) {
                    // If it's by the trusted key and newer than the last one...
                    if (
                        Uint8ArrayToHex(cert.issuerFingerprint || []) ==
                            fingerprint &&
                        cert.created &&
                        isAfter(cert.created, latestTime) &&
                        !cert.revoked // This excludes revocations.
                    ) {
                        /* Force verify it for good measure, that data should
                        be cached. */

                        const verified = await uid.verifyCertificate(cert, [
                            trustedKey,
                        ]);

                        if (verified) {
                            // This might be a relevant signature.
                            relevantSignature = index;
                            latestTime = cert.created;
                        }
                    }
                }

                // None of the signatures are relevant, so try next trusted key.
                if (relevantSignature < 0) {
                    continue next_trusted_key;
                }

                /* If the relevant signature has more than one notation with
                the correct name, we skip to the next key. The OpenPGP
                standard technically allows more than one notation with the
                same name. HQSL does not: a lot of libraries do not properly
                support this. */

                const relevantNotations = uid.otherCertifications[
                    relevantSignature
                ].rawNotations.filter((x) => x.name === notationName);

                if (relevantNotations.length != 1) {
                    continue next_trusted_key;
                }

                // Now we can parse it.
                const components = new TextDecoder("utf-8")
                    .decode(relevantNotations[0].value)
                    .split(",");

                /* The first token is the callsign being certified, the rest
                are pairs of start/end datetimes. So check that the number of
                tokens is odd and the first token matches the callsign: */

                if (components.length % 2 == 1 && components[0] == call) {
                    // We need to iterate over pairs of datetimes now
                    for (let i = 1; i < components.length; i += 2) {
                        const start = fromHamDate(components[i]);
                        const end = fromHamDate(components[i + 1]);
                        // Invalid pairs are also ignored
                        if (isAfter(end, start)) {
                            results.push({
                                call: call,
                                start: start,
                                end: end,
                                key: trustedKey,
                            });
                        }
                    }
                }
            }
        }

        return results;
    }

    /**
     * Sign a HQSL object.
     *
     * @param qsl The object to sign.
     * @param key Private key object.
     * @param passphrase Passphrase, required if the key is locked.
     * @param signingDate Signature date.
     * @returns
     */
    async sign(
        qsl: HQSL,
        key: PrivateKey,
        passphrase?: string,
        signingDate?: Date
    ): Promise<HQSL> {
        const unsignedMessage = await createMessage({
            text: qsl.signedData,
            format: "binary", // Eschew ambiguity.
        });

        const signingKey = key.isDecrypted()
            ? key
            : await decryptKey({
                  privateKey: key,
                  passphrase: passphrase || "",
              });

        qsl.signature = await sign({
            message: unsignedMessage,
            detached: true,
            format: "binary",
            signingKeys: signingKey,
            date: signingDate || new Date(),
            config: pgpConfig,
        });

        return qsl;
    }

    /* Technically it's none of this class' business. But this is the most
    convenient place to keep this, since we're not using a separate HKP
    library. I'm not entirely sure how much erroring is appropriate. */

    /**
     * Publish a public key to the HKP key servers.
     *
     * @param key The key to publish.
     * @param targetKeyServer Will attempt to publish the key to ALL
     *                        key servers known, unless this parameter
     *                        is a key server URL.
     */
    async publish(key: PublicKey, targetKeyServer?: string) {
        for (const keyServer of targetKeyServer
            ? [normalizeUrl(targetKeyServer)]
            : this.keyServers) {
            // Normalized keyserver url includes a slash.
            fetchWithTimeout(`${keyServer}pks/add`, {
                timeout: this.timeout,
                method: "post",
                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded; charset=UTF-8",
                },
                body: "keytext=" + encodeURIComponent(key.armor()),
            });
        }
    }
}

/**
 * Shorthand to format a callsign for user ID.
 * @param c Callsign
 * @returns
 * @throws `Error` if the callsign does not conform to the regular expression used for matching them.
 */
export function callID(c: string): string {
    if (!c.match(callsignRe)) {
        throw new Error("Malformed callsign")
    }
    return `Amateur Radio Callsign: ${c}`;
}

// Config parameters for key and signature creation which get reused multiple times.
const pgpConfig = {
    // This is effectively ProtonMail specific, and when true
    // bumps the size of a signature by a third.
    nonDeterministicSignaturesViaNotation: false,
    // We explicitly don't make v6 keys, they're far from widely supported yet.
    v6Keys: false,
}


/**
 * A shorthand function to generate a signer key in a way that is
 * known to be compatible with all existing HQSL implementations and should
 * be widely supported. Produces an OpenPGP v4/ed25519 key with no salted
 * signatures.
 * 
 * Since one key owner may use many different call signs, and often, 
 * a call sign may have multiple people using it over time or even 
 * simultaneously, it is most reasonable to have the primary user ID
 * identify the key owner in whichever way is most expedient 
 * (Hamlog.Online uses plain integer IDs) while all the
 * callsigns it claims are expressed in additional user IDs.
 *
 * @param userid The primary User ID string.
 * @param calls An array of callsigns for this key to claim. 
 *              Must contain pure callsigns with no slashes,
 *              or be an empty array.
 * @throws `Error` if any of the the call signs given were not valid.
 */
export async function generateSignerKey(userid: string, calls: string[]) : Promise<{
    privateKey: PrivateKey,
    publicKey: PublicKey,
    revocationCertificate: string
}>{
    const userIDs = [{ name: userid }].concat(
        calls.map((c) => {
            return { name: callID(c) };
        })
    );

    const { privateKey, publicKey, revocationCertificate } = await generateKey({
        type: "ecc",
        curve: "curve25519Legacy",
        userIDs: userIDs,
        format: "object",
        config: pgpConfig,
    });

    return {
        privateKey: privateKey,
        publicKey: publicKey,
        revocationCertificate: revocationCertificate
    }
}

/**
 * Go through a key to collect all the callsigns it claims, whether they are certified or not.
 * For consistency, callsigns are returned in alphabetical order, rather than in the order they
 * appear in the key.
 * 
 * @param key The key in question
 * @returns An array of callsigns.
 */
export function listCalls(key: PrivateKey | PublicKey): string[] {
    return key
        .getUserIDs()
        .filter((uid) => uid.match(uidRe))
        .map((uid) => uid.replace(uidRe, "$1"))
        .sort((a, b) => a.localeCompare(b));
}

/**
 * When the list of callsigns a key claims must change, you need to add a self-signed user ID to it
 * before that user ID can be certified, since no key server will accept a user ID that is not self-signed.
 * With OpenPGPjs the process of adding an extra user ID to a key is far from straightforward,
 * which is why this function is there.
 * 
 * To actually make this happen, we need to build a new key object using existing key material from 
 * a given key, but with a completely new set of *two* userID objects on it. Bizarrely, this is the most
 * expedient way to create a new self-signed userID with OpenPGPjs.
 *
 * Then we take the *second* user ID created this way (the first one is marked primary and
 * would result in a key with two primary IDs) on the newly produced key object and graft it back
 * into the structure of the original key. Once the key is serialized again, everything will be correct.
 * 
 * Beware, this modifies the key in place.
 * 
 * @param key a private key.
 * @param callsign The callsign to claim.
 * @returns 
 */
export async function addUserID(
    key: PrivateKey,
    callsign: string
): Promise<PrivateKey> {
    
    const temporaryKeyPair = await reformatKey({
        privateKey: key,
        userIDs: [{ name: "dummy" }, { name: callID(callsign) }],
        format: "object",
        config: pgpConfig
    });

    // Copy out the *second* user from the rebuilt key and stick it into the old key.
    const newUser = (temporaryKeyPair.privateKey.users[1] as any).clone();
    newUser.mainKey = (key.users[0] as any).mainKey;
    key.users.push(newUser);

    return key;
}
