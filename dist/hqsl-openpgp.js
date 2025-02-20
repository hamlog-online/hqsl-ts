import { PublicKey, readKeys, readSignature, createMessage, verify, sign, decryptKey, generateKey, reformatKey, } from "openpgp";
import { isAfter, isBefore } from "date-fns";
import { callsignRe } from "./hqsl";
import { HQSLState } from "./hqsl-verification";
import { Uint8ArrayToHex, fetchWithTimeout } from "./util/misc";
import { fromHamDate } from "./util/date";
const uidRe = /^Amateur Radio Callsign: ([0-9A-Z-]+)$/g;
const notationName = "qsl@hqsl.net";
function normalizeUrl(url) {
    let newUrl = new URL(url);
    let result = newUrl.href;
    if (newUrl.protocol == "hkps:") {
        newUrl.protocol = "https";
        result = newUrl.href.replace(/^hkps:/, "https:");
    }
    else if (newUrl.protocol == "hkp:") {
        newUrl.protocol = "http";
        newUrl.port = newUrl.port || "11371";
        result = newUrl.href.replace(/^hkp:/, "http:");
    }
    if (!result.endsWith("/")) {
        result += "/";
    }
    return result;
}
export class HQSLOpenPGP {
    constructor(trustedKeys, keyServers, timeout) {
        this.keyServers = [];
        this.trustedKeys = trustedKeys;
        for (const url of keyServers) {
            this.keyServers.push(normalizeUrl(url));
        }
        this.timeout = timeout;
    }
    static async setup(trustedKeys, keyServers, timeout) {
        let keys = [];
        for (const key of trustedKeys) {
            if (typeof key === "string") {
                keys = keys.concat(await readKeys({ armoredKeys: key }));
            }
            else if (key instanceof Uint8Array) {
                keys = keys.concat(await readKeys({ binaryKeys: key }));
            }
            else if (key instanceof PublicKey) {
                keys.push(key);
            }
        }
        return new HQSLOpenPGP(keys, keyServers && keyServers.length ? keyServers : ["https://hqsl.net"], timeout || 1000);
    }
    async lookup(query) {
        for (const baseUrl of this.keyServers) {
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
                    console.error(`Server ${baseUrl} returned something other than an OpenPGP key.`);
                }
            }
            catch (error) {
                console.error(`Public key server ${baseUrl} timed out.`);
            }
        }
        throw new Error("Key not found");
    }
    async verify(qsl) {
        var _a;
        if (qsl === undefined) {
            return qsl;
        }
        if (!qsl.from || !qsl.when) {
            qsl.verification = { verdict: HQSLState.Invalid };
            return qsl;
        }
        qsl.verification = undefined;
        if (!qsl.signature) {
            qsl.verification = { verdict: HQSLState.NotSigned };
            return qsl;
        }
        let sig;
        try {
            sig = await readSignature({
                binarySignature: qsl.signature,
            });
        }
        catch (error) {
            qsl.verification = { verdict: HQSLState.Invalid };
            return qsl;
        }
        const message = await createMessage({
            text: qsl.signedData,
            format: "binary",
        });
        const signers = sig.getSigningKeyIDs();
        if (signers.length != 1) {
            qsl.verification = { verdict: HQSLState.Invalid };
            return qsl;
        }
        const signingKeyId = signers[0].toHex();
        let foundKeys;
        try {
            foundKeys = await this.lookup(`0x${signingKeyId}`);
        }
        catch (error) {
            qsl.verification = { verdict: HQSLState.KeyNotFound };
            return qsl;
        }
        next_key: for (const signerKey of foundKeys) {
            const verificationResult = await verify({
                message: message,
                signature: sig,
                verificationKeys: signerKey,
                format: "binary",
            });
            for (const check of verificationResult.signatures) {
                try {
                    await check.verified;
                    break;
                }
                catch (e) {
                    continue next_key;
                }
            }
            const chunks = ((_a = qsl.from) === null || _a === void 0 ? void 0 : _a.split("/")) || [];
            const matchingRanges = (await this.getCertifications(signerKey)).filter((x) => chunks.includes(x.call));
            for (const range of matchingRanges) {
                if (isAfter(qsl.when, range.start) &&
                    isBefore(qsl.when, range.end)) {
                    qsl.verification = {
                        verdict: HQSLState.Valid,
                        signerKey: signerKey,
                        certifierKey: range.key,
                    };
                    return qsl;
                }
            }
            qsl.verification = {
                verdict: HQSLState.KeyNotCertified,
                signerKey: signerKey,
            };
            return qsl;
        }
        qsl.verification = { verdict: HQSLState.Invalid };
        return qsl;
    }
    async getCertifications(key) {
        var _a;
        const results = [];
        try {
            await key.verifyPrimaryKey();
        }
        catch (e) {
            return results;
        }
        await key.verifyAllUsers(this.trustedKeys);
        for (const uid of key.users.filter((x) => x.userID && x.userID.userID.match(uidRe))) {
            const call = (_a = uid.userID) === null || _a === void 0 ? void 0 : _a.userID.replace(uidRe, "$1");
            try {
                await uid.verify();
            }
            catch (e) {
                continue;
            }
            next_trusted_key: for (const trustedKey of this.trustedKeys) {
                const fingerprint = trustedKey === null || trustedKey === void 0 ? void 0 : trustedKey.getFingerprint();
                let relevantSignature = -1;
                let latestTime = new Date(1970);
                for (const [index, cert] of uid.otherCertifications.entries()) {
                    if (Uint8ArrayToHex(cert.issuerFingerprint || []) ==
                        fingerprint &&
                        cert.created &&
                        isAfter(cert.created, latestTime) &&
                        !cert.revoked) {
                        const verified = await uid.verifyCertificate(cert, [
                            trustedKey,
                        ]);
                        if (verified) {
                            relevantSignature = index;
                            latestTime = cert.created;
                        }
                    }
                }
                if (relevantSignature < 0) {
                    continue next_trusted_key;
                }
                const relevantNotations = uid.otherCertifications[relevantSignature].rawNotations.filter((x) => x.name === notationName);
                if (relevantNotations.length != 1) {
                    continue next_trusted_key;
                }
                const components = new TextDecoder("utf-8")
                    .decode(relevantNotations[0].value)
                    .split(",");
                if (components.length % 2 == 1 && components[0] == call) {
                    for (let i = 1; i < components.length; i += 2) {
                        const start = fromHamDate(components[i]);
                        const end = fromHamDate(components[i + 1]);
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
    async sign(qsl, key, passphrase, signingDate) {
        const unsignedMessage = await createMessage({
            text: qsl.signedData,
            format: "binary",
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
    async publish(key, targetKeyServer) {
        for (const keyServer of targetKeyServer
            ? [normalizeUrl(targetKeyServer)]
            : this.keyServers) {
            fetchWithTimeout(`${keyServer}pks/add`, {
                timeout: this.timeout,
                method: "post",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                },
                body: "keytext=" + encodeURIComponent(key.armor()),
            });
        }
    }
}
export function callID(c) {
    if (!c.match(callsignRe)) {
        throw new Error("Malformed callsign");
    }
    return `Amateur Radio Callsign: ${c}`;
}
const pgpConfig = {
    nonDeterministicSignaturesViaNotation: false,
    v6Keys: false,
};
export async function generateSignerKey(userid, calls) {
    const userIDs = [{ name: userid }].concat(calls.map((c) => {
        return { name: callID(c) };
    }));
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
    };
}
export function listCalls(key) {
    return key
        .getUserIDs()
        .filter((uid) => uid.match(uidRe))
        .map((uid) => uid.replace(uidRe, "$1"))
        .sort((a, b) => a.localeCompare(b));
}
export async function addUserID(key, callsign) {
    const temporaryKeyPair = await reformatKey({
        privateKey: key,
        userIDs: [{ name: "dummy" }, { name: callID(callsign) }],
        format: "object",
        config: pgpConfig
    });
    const newUser = temporaryKeyPair.privateKey.users[1].clone();
    newUser.mainKey = key.users[0].mainKey;
    key.users.push(newUser);
    return key;
}
//# sourceMappingURL=hqsl-openpgp.js.map