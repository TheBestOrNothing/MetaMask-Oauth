/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

var express = require('express');

const authProvider = require('../metamask/AuthProvider');
const { REDIRECT_URI, POST_LOGOUT_REDIRECT_URI } = require('../authConfig');

const router = express.Router();

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

module.exports = router;
