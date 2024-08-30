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


express.use(express.json());

const verifyMetaMaskToken = (req, res, next) => {
    // Check for the token in the request body
    const mmToken = req.body.mmToken;  // Assuming the mmToken is sent under the 'token' key in the JSON body

    if (mmToken && mmToken.split('.').length === 2) {
        const parts = mmToken.split('.');
        const msgParams = JSON.parse(base64url.decode(parts[0]));
        const sign = parts[1];            
        const from = msgParams.message.account;
        const recoveredAddr = recoverTypedSignature({
            data: msgParams,
            signature: sign,
            version: 'V4',
        });

        console.log(recoveredAddr);

        if (toChecksumAddress(recoveredAddr) === toChecksumAddress(from)) {
            console.log(`Successfully verified signer as ${recoveredAddr}`);
            req.account = from;
            next();
        } else {
            console.log(
            `Failed to verify signer when comparing ${recoveredAddr} to ${from}`,
            );
            return res.redirect('/mmCode');
        }

    } else {
        // If no token is present, redirect to get a new token
        return res.redirect('/mmCode');
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

router.get('/mmCode', authProvider.getQR({
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI
}));

router.get('/mmToken/:mmCode', authProvider.mmTokenGenerate({
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI
}));

router.get('/getSelectedAccount', verifyMetaMaskToken, authProvider.getSelectedAccount({
    postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI
}));

module.exports = router;
