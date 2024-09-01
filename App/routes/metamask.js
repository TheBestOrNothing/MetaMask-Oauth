/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

var express = require('express');

const authProvider = require('../metamask/AuthProvider');
const { REDIRECT_URI, POST_LOGOUT_REDIRECT_URI } = require('../authConfig');

const router = express.Router();
const base64url = require('base64url');
const { toChecksumAddress } = require('ethereumjs-util');

const {
  encrypt,
  recoverPersonalSignature,
  recoverTypedSignature,
} = require('@metamask/eth-sig-util');


const verifyMetaMaskToken = (req, res, next) => {
    // Check for the token in the request body
    const mmToken = req.body.mmToken;  // Assuming the mmToken is sent under the 'token' key in the JSON body

    console.log(mmToken);
    console.log(mmToken.split('.').length);
    if (mmToken && mmToken.split('.').length == 3) {
        console.log("in the if statement");
        const parts = mmToken.split('.');

        const timestampStr = parts[0];
        const account = parts[1];
        const sign = parts[2];

        const timestamp = BigInt(timestampStr);

        let timeout = false;
        if(Math.floor(Date.now()/1000) > timestamp) {
            // Token has expired, terminate the session and remove from MetaMaskSDKManager
            timeout = true;
        }

        const msgParams = {
            domain: {
              chainId: '0x1',
              name: 'RocketChat Login',
              verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
              version: '1',
            },
            message: {
              account: account,
              timestamp: timestamp,
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
                { name: 'account', type: 'string' },
                { name: 'timestamp', type: 'uint256' },
              ],
            },
          };

        try {
            const recoveredAddr = recoverTypedSignature({
                data: msgParams,
                signature: sign,
                version: 'V4',
            });

            console.log(recoveredAddr);

            if (!timeout && toChecksumAddress(recoveredAddr) === toChecksumAddress(account)) {
                console.log(`Successfully verified signer as ${recoveredAddr}`);
                req.account = account;
                next();
            } else {
                if(timeout) {   // Token has expired
                    console.log(`Token has expired`);
                } else {
                    console.log(`Failed to verify signer when comparing ${recoveredAddr} to ${from}`);
                }
                return res.redirect('/metamask/mmCode');
            }
        } catch (e) {
            console.error(e);
            return res.redirect('/metamask/mmCode');
        }
    } else {
        // If no token is present, redirect to get a new token
        return res.redirect('/metamask/mmCode');
    }
};

router.get('/signin', authProvider.login({
    scopes: [],
    redirectUri: REDIRECT_URI,
    successRedirect: '/'
}));

router.get('/acquireToken', authProvider.acquireToken({
    scopes: ['User.Read'],
    redirectUri: REDIRECT_URI,
    successRedirect: '/users/profile'
}));

router.post('/redirect', authProvider.handleRedirect());

router.get('/signout', authProvider.logout({
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI
}));

router.get('/authorize', authProvider.getWalletAddress({
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI
}));

router.post('/token', authProvider.token({
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI
}));

router.get('/userinfo', authProvider.userinfo({
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI
}));

//router.get('/mmCode', authProvider.getQR({
router.get('/mmCode', authProvider.mmCode({
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI
}));

//router.get('/mmToken/:mmCode', authProvider.mmTokenGenerate({
router.post('/mmToken', authProvider.mmToken({
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI
}));

router.post('/getSelectedAccount', verifyMetaMaskToken, authProvider.getSelectedAccount({
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI
}));

module.exports = router;
