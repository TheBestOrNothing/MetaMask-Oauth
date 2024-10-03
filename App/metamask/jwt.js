const msal = require('@azure/msal-node');
const axios = require('axios');
var path = require('path');
const { createCanvas, loadImage } = require('canvas');
const fs = require('fs'); // Import the file system module
const { toChecksumAddress } = require('ethereumjs-util');
const QRCode = require('qrcode');

const { msalConfig } = require('../authConfig');
const publicKeyToAddress = require('ethereum-public-key-to-address');
const jose = require('jose');
const crypto = require('crypto');
const secp = require('noble-secp256k1');

const {
    encrypt,
    recoverPersonalSignature,
    recoverTypedSignature,
} = require('@metamask/eth-sig-util');

const { type } = require('os');
const { sign } = require('crypto');
const { get } = require('http');

const getMsgParams = (account, expireTime) => {

        // Create a new Date object
        const dateObject = new Date(expireTime); 
        // Convert to ISO 8601 string
        const isoString = dateObject.toISOString();

        const msgParams = {
            domain: {
                chainId: '0x1',
                name: 'RocketChat Login',
                verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
                version: '1',
            },
            message: {
                exp: isoString,
                iss: account,
            },
            primaryType: 'Code',
            types: {
                EIP712Domain: [
                    { name: 'name', type: 'string' },
                    { name: 'version', type: 'string' },
                    { name: 'chainId', type: 'uint256' },
                    { name: 'verifyingContract', type: 'address' },
                ],
                Code: [
                    { name: 'iss', type: 'string' },
                    { name: 'exp', type: 'string' },
                ],
            },
        };

        return msgParams;
    };

const genJWTByNode = async () => {

    //{
    //        kty: 'EC',
    //        x: '2QEVXJBpeCRdIG4HlMiOxcthoUxPlpc5qYmPjbAF2b0',
    //        y: 'onJDpWsKJ_uFzvA3RiMPQ_3TJwWSgejSVtNdrWx_HKo',
    //        crv: 'secp256k1',
    //        d: 'x1p07QZHIKvbk5kic6Kj48ZnDL5Yy_svPVBZzn0VMoU'
    //}
    //c75a74ed064720abdb93992273a2a3e3c6670cbe58cbfb2f3d5059ce7d153285
    //0x4477610799E7910F0e40F64dA702aa9fFcF929ac

    const importedPrivateKeyHex = "c75a74ed064720abdb93992273a2a3e3c6670cbe58cbfb2f3d5059ce7d153285";
    const importedPrivateKeyBase64url = Buffer.from(importedPrivateKeyHex, 'hex').toString('base64url');
    console.log(importedPrivateKeyBase64url);

    const importedPrivateKeyJWK = await jose.importJWK(
        {
            kty: 'EC',
            x: '2QEVXJBpeCRdIG4HlMiOxcthoUxPlpc5qYmPjbAF2b0',
            y: 'onJDpWsKJ_uFzvA3RiMPQ_3TJwWSgejSVtNdrWx_HKo',
            crv: 'secp256k1',
            d: 'x1p07QZHIKvbk5kic6Kj48ZnDL5Yy_svPVBZzn0VMoU'
        },
        'ES256K',
    );

    const jwt = await new jose.SignJWT({ 'urn:example:claim': true })
        .setProtectedHeader({ alg: 'ES256K' })
        .setIssuedAt()
        .setIssuer('urn:example:issuer')
        .setAudience('urn:example:audience')
        .setExpirationTime('2h')
        .sign(importedPrivateKeyJWK)

    exportedPrivateKey = importedPrivateKeyJWK.export({
        type: 'sec1',
        format: 'jwk'
    });
    dHex = Buffer.from(exportedPrivateKey.d, 'base64url').toString('hex');

    const { payload, protectedHeader } = await jose.jwtVerify(jwt, importedPrivateKeyJWK, {
        issuer: 'urn:example:issuer',
        audience: 'urn:example:audience',
    });

    console.log("....................................................");
    console.log(protectedHeader);
    console.log(payload);
    console.log("importePrivateKeyhex:");
    console.log(importedPrivateKeyHex);
    console.log("exportedPrivateKeyHex:");
    console.log(dHex);
    console.log("JWT:");
    console.log(jwt);
    console.log("");

    // Convert header and payload to base64url-encoded strings
    const encodedHeader = Buffer.from(JSON.stringify(protectedHeader)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    //console.log(encodedHeader);
    //console.log(encodedPayload);

    // Create the data to be signed (header and payload)
    const dataToSign = `${encodedHeader}.${encodedPayload}`;
    jwtData = dataToSign;

    const dataToSignUint8array = new TextEncoder().encode(dataToSign);

    // Generate a private key (for example purposes, you might want to use an existing private key)
    // const privateKey = secp.utils.randomPrivateKey();
    // Convert the private key from hex string to a byte array
    // Validate the private key
    if (!secp.utils.isValidPrivateKey(dHex)) {
        throw new Error('Invalid private key');
    }

    const sign = crypto.sign('sha256', dataToSignUint8array, importedPrivateKeyJWK);
    //const sign = crypto.sign('sha256', dataToSignUint8array, { dsaEncoding: 'ieee-p1363', importedPrivateKeyJWK});
    const signatureBase64url = Buffer.from(sign).toString('base64url');
    // Combine header, payload, and signature to form the JWT
    const jwt1 = `${dataToSign}.${signatureBase64url}`;

    console.log('JWT regenerated:');
    console.log(jwt1);

    // Hash the data using SHA-256 (required before signing with secp256k1)
    const hashedDataUint8Array = await secp.utils.sha256(dataToSignUint8array);

    // Sign the hashed data
    const signatureUint8Array = await secp.sign(hashedDataUint8Array, dHex, { extraEntropy: false });
    const signatureBase64url2 = Buffer.from(signatureUint8Array).toString('base64url')

    // Combine header, payload, and signature to form the JWT
    const jwt2 = `${dataToSign}.${signatureBase64url2}`;

    console.log('JWT regenerated:');
    console.log(jwt2);
    console.log("....................................................");
}

const testJWT = async () => {

    //await getAddressbyPrivateKey();
    const { publicKey, privateKey } = await jose.generateKeyPair('ES256K');

    // Export the public key in jwk format
    const exportedPublicKey = publicKey.export({
        type: 'spki',
        format: 'jwk'
    });

    // Export the private key in jwk format
    let exportedPrivateKey = privateKey.export({
        type: 'sec1',
        format: 'jwk'
    });
    console.log(exportedPublicKey);
    console.log(exportedPrivateKey);

    const xHex = Buffer.from(exportedPublicKey.x, 'base64url').toString('hex');
    const yHex = Buffer.from(exportedPublicKey.y, 'base64url').toString('hex');
    let dHex = Buffer.from(exportedPrivateKey.d, 'base64url').toString('hex');
    console.log(xHex.length);
    console.log(yHex.length);
    console.log(dHex);

    const uncompressedPublicKey = `04${xHex}${yHex}`;
    const address = publicKeyToAddress(uncompressedPublicKey);
    console.log(address);

    //{
    //        kty: 'EC',
    //        x: '2QEVXJBpeCRdIG4HlMiOxcthoUxPlpc5qYmPjbAF2b0',
    //        y: 'onJDpWsKJ_uFzvA3RiMPQ_3TJwWSgejSVtNdrWx_HKo',
    //        crv: 'secp256k1',
    //        d: 'x1p07QZHIKvbk5kic6Kj48ZnDL5Yy_svPVBZzn0VMoU'
    //}
    //c75a74ed064720abdb93992273a2a3e3c6670cbe58cbfb2f3d5059ce7d153285
    //0x4477610799E7910F0e40F64dA702aa9fFcF929ac

    const importedPrivateKeyHex = "c75a74ed064720abdb93992273a2a3e3c6670cbe58cbfb2f3d5059ce7d153285";
    const importedPrivateKeyBase64url = Buffer.from(importedPrivateKeyHex, 'hex').toString('base64url');
    console.log(importedPrivateKeyBase64url);

    const importedPrivateKeyJWK = await jose.importJWK(
        {
            kty: 'EC',
            x: '2QEVXJBpeCRdIG4HlMiOxcthoUxPlpc5qYmPjbAF2b0',
            y: 'onJDpWsKJ_uFzvA3RiMPQ_3TJwWSgejSVtNdrWx_HKo',
            crv: 'secp256k1',
            d: 'x1p07QZHIKvbk5kic6Kj48ZnDL5Yy_svPVBZzn0VMoU'
        },
        'ES256K',
    );

    const jwt = await new jose.SignJWT({ 'urn:example:claim': true })
        .setProtectedHeader({ alg: 'ES256K' })
        .setIssuedAt()
        .setIssuer('urn:example:issuer')
        .setAudience('urn:example:audience')
        .setExpirationTime('2h')
        .sign(importedPrivateKeyJWK)

    exportedPrivateKey = importedPrivateKeyJWK.export({
        type: 'sec1',
        format: 'jwk'
    });
    dHex = Buffer.from(exportedPrivateKey.d, 'base64url').toString('hex');

    const { payload, protectedHeader } = await jose.jwtVerify(jwt, importedPrivateKeyJWK, {
        issuer: 'urn:example:issuer',
        audience: 'urn:example:audience',
    });

    console.log("....................................................");
    console.log(protectedHeader);
    console.log(payload);
    console.log("privateKey hex:");
    console.log(dHex);
    console.log("JWT:");
    console.log(jwt);
    console.log("");


    // Convert header and payload to base64url-encoded strings
    const encodedHeader = Buffer.from(JSON.stringify(protectedHeader)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    console.log(encodedHeader);
    console.log(encodedPayload);

    // Create the data to be signed (header and payload)
    const dataToSign = `${encodedHeader}.${encodedPayload}`;
    jwtData = dataToSign;

    const dataToSignUint8array = new TextEncoder().encode(dataToSign);
    // Generate a private key (for example purposes, you might want to use an existing private key)
    // const privateKey = secp.utils.randomPrivateKey();
    // Convert the private key from hex string to a byte array
    // Validate the private key
    if (!secp.utils.isValidPrivateKey(dHex)) {
        throw new Error('Invalid private key');
    }

    // Hash the data using SHA-256 (required before signing with secp256k1)
    const hashedDataUint8Array = await secp.utils.sha256(dataToSignUint8array);

    // Sign the hashed data
    const signatureUint8Array = await secp.sign(hashedDataUint8Array, dHex);
    const signatureBase64url = Buffer.from(signatureUint8Array).toString('base64url')
    console.log(signatureBase64url);

    // Combine header, payload, and signature to form the JWT
    const jwt1 = `${dataToSign}.${signatureBase64url}`;

    console.log('JWT regenerated:');
    console.log(jwt1);
    console.log("....................................................");
};

const jwtSign = async (sdk, account) => {
    const provider = sdk.getProvider();

    try {
        const dataToSignUint8array = new TextEncoder().encode(jwtData);
        const dataToSignHex = Buffer.from(dataToSignUint8array).toString('hex');
        const msg = `0x${dataToSignHex}`;
        const sign = await provider.request({
            method: 'personal_sign',
            params: [msg, account],
        });
        console.log("jwtData:", jwtData);
        console.log('new signment:');
        console.warn(sign);
        console.log('new signment base64url:');
        console.warn(Buffer.from(sign.slice(2), 'hex').toString('base64url'));

    } catch (err) {
        console.error(err);
    }

    //Why not following code with base64url not stable ??
    //const msgParamsBase64Url = base64url.encode(JSON.stringify(msgParams));
    //const mmToken = `${msgParamsBase64Url}.${sign}`;
}


//module.exports = testJWT; 
//module.exports = genJWTByNode; 
module.exports = getMsgParams; 