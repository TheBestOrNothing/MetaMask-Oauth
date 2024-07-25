const msal = require('@azure/msal-node');
const axios = require('axios');
var path = require('path');

const { msalConfig } = require('../authConfig');

const {
  encrypt,
  recoverPersonalSignature,
  recoverTypedSignature,
} = require('@metamask/eth-sig-util');

const crypto = require('crypto');
const { time } = require('console');
const { toChecksumAddress } = require('ethereumjs-util');

class AuthProvider {
    msalConfig;
    cryptoProvider;
    users;

    constructor(msalConfig) {
        this.msalConfig = msalConfig
        this.cryptoProvider = new msal.CryptoProvider();
        this.users = new Map();
    };

    login(options = {}) {
        return async (req, res, next) => {

            /**
             * MSAL Node library allows you to pass your custom state as state parameter in the Request object.
             * The state parameter can also be used to encode information of the app's state before redirect.
             * You can pass the user's state in the app, such as the page or view they were on, as input to this parameter.
             */
            const state = this.cryptoProvider.base64Encode(
                JSON.stringify({
                    successRedirect: options.successRedirect || '/',
                })
            );

            const authCodeUrlRequestParams = {
                state: state,

                /**
                 * By default, MSAL Node will add OIDC scopes to the auth code url request. For more information, visit:
                 * https://docs.microsoft.com/azure/active-directory/develop/v2-permissions-and-consent#openid-connect-scopes
                 */
                scopes: options.scopes || [],
                redirectUri: options.redirectUri,
            };

            const authCodeRequestParams = {
                state: state,

                /**
                 * By default, MSAL Node will add OIDC scopes to the auth code request. For more information, visit:
                 * https://docs.microsoft.com/azure/active-directory/develop/v2-permissions-and-consent#openid-connect-scopes
                 */
                scopes: options.scopes || [],
                redirectUri: options.redirectUri,
            };

            /**
             * If the current msal configuration does not have cloudDiscoveryMetadata or authorityMetadata, we will 
             * make a request to the relevant endpoints to retrieve the metadata. This allows MSAL to avoid making 
             * metadata discovery calls, thereby improving performance of token acquisition process. For more, see:
             * https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/lib/msal-node/docs/performance.md
             */
            if (!this.msalConfig.auth.cloudDiscoveryMetadata || !this.msalConfig.auth.authorityMetadata) {

                const [cloudDiscoveryMetadata, authorityMetadata] = await Promise.all([
                    this.getCloudDiscoveryMetadata(this.msalConfig.auth.authority),
                    this.getAuthorityMetadata(this.msalConfig.auth.authority)
                ]);

                this.msalConfig.auth.cloudDiscoveryMetadata = JSON.stringify(cloudDiscoveryMetadata);
                this.msalConfig.auth.authorityMetadata = JSON.stringify(authorityMetadata);
            }

            const msalInstance = this.getMsalInstance(this.msalConfig);

            // trigger the first leg of auth code flow
            return this.redirectToAuthCodeUrl(
                authCodeUrlRequestParams,
                authCodeRequestParams,
                msalInstance
            )(req, res, next);
        };
    }

    acquireToken(options = {}) {
        return async (req, res, next) => {
            try {
                const msalInstance = this.getMsalInstance(this.msalConfig);

                /**
                 * If a token cache exists in the session, deserialize it and set it as the 
                 * cache for the new MSAL CCA instance. For more, see: 
                 * https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/lib/msal-node/docs/caching.md
                 */
                if (req.session.tokenCache) {
                    msalInstance.getTokenCache().deserialize(req.session.tokenCache);
                }

                const tokenResponse = await msalInstance.acquireTokenSilent({
                    account: req.session.account,
                    scopes: options.scopes || [],
                });

                /**
                 * On successful token acquisition, write the updated token 
                 * cache back to the session. For more, see: 
                 * https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/lib/msal-node/docs/caching.md
                 */
                req.session.tokenCache = msalInstance.getTokenCache().serialize();
                req.session.accessToken = tokenResponse.accessToken;
                req.session.idToken = tokenResponse.idToken;
                req.session.account = tokenResponse.account;

                res.redirect(options.successRedirect);
            } catch (error) {
                if (error instanceof msal.InteractionRequiredAuthError) {
                    return this.login({
                        scopes: options.scopes || [],
                        redirectUri: options.redirectUri,
                        successRedirect: options.successRedirect || '/',
                    })(req, res, next);
                }

                next(error);
            }
        };
    }

    handleRedirect(options = {}) {
        return async (req, res, next) => {
            if (!req.body || !req.body.state) {
                return next(new Error('Error: response not found'));
            }

            const authCodeRequest = {
                ...req.session.authCodeRequest,
                code: req.body.code,
                codeVerifier: req.session.pkceCodes.verifier,
            };

            try {
                const msalInstance = this.getMsalInstance(this.msalConfig);

                if (req.session.tokenCache) {
                    msalInstance.getTokenCache().deserialize(req.session.tokenCache);
                }

                const tokenResponse = await msalInstance.acquireTokenByCode(authCodeRequest, req.body);

                req.session.tokenCache = msalInstance.getTokenCache().serialize();
                req.session.idToken = tokenResponse.idToken;
                req.session.account = tokenResponse.account;
                req.session.isAuthenticated = true;

                const state = JSON.parse(this.cryptoProvider.base64Decode(req.body.state));
                res.redirect(state.successRedirect);
            } catch (error) {
                next(error);
            }
        }
    }

    logout(options = {}) {
        return (req, res, next) => {

            /**
             * Construct a logout URI and redirect the user to end the
             * session with Azure AD. For more information, visit:
             * https://docs.microsoft.com/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request
             */
            let logoutUri = `${this.msalConfig.auth.authority}/oauth2/v2.0/`;

            if (options.postLogoutRedirectUri) {
                logoutUri += `logout?post_logout_redirect_uri=${options.postLogoutRedirectUri}`;
            }

            req.session.destroy(() => {
                res.redirect(logoutUri);
            });
        }
    }

    getWalletAddress(options = {}) {
        return async (req, res, next) => {
            res.sendFile(path.join(__dirname, '..', 'public', 'indexMetaMask.html'));
        }
    }

    personalSignVerify(state, stateSign) {
        try {
          const stateHex = `0x${Buffer.from(state, 'utf8').toString('hex')}`;
          const recoveredAddr = recoverPersonalSignature({
            data: stateHex,
            signature: stateSign,
          });
            console.log(`SigUtil Successfully verified signer as ${recoveredAddr}`);
        } catch (err) {
            console.error(err);
        }
    };

    personalSignVerify(timestamp, account, sign) {
    
        const time = BigInt(timestamp);
        console.log(time.toString());

        const msgParams = {
          domain: {
            chainId: '0x1',
            name: 'RocketChat Login',
            verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
            version: '1',
          },
          message: {
            account: account,
            timestamp: time,
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
            const from = account;
            const recoveredAddr = recoverTypedSignature({
                data: msgParams,
                signature: sign,
                version: 'V4',
            });

            console.log(recoveredAddr);

            if (toChecksumAddress(recoveredAddr) === toChecksumAddress(from)) {
                console.log(`Successfully verified signer as ${recoveredAddr}`);
                return true;
            } else {
                console.log(
                `Failed to verify signer when comparing ${recoveredAddr} to ${from}`,
                );
                return false;
            }
        } catch (err) {
            console.error(err);
            return false;
        }
    };

    token(options = {}) {
        return (req, res, next) => {

            const code = req.body.code;
            console.log("Code ............", code);
            const codeParts = code.split('.');
            console.log("Code ............", codeParts);
            const timestamp = codeParts[0];
            const account = codeParts[1];
            const sign = codeParts[2];

            if(this.personalSignVerify(timestamp, account, sign)){
                const tokenResponse = {
                    token_type: 'Bearer',
                    expires_in: '3599',
                    ext_expires_in: '3599',
                    expires_on: '1717638666',
                    access_token: sign,
                    refresh_token: sign,
                    id_token: sign 
                };

                const user = {
                    amr: '["pwd","mfa"]',
                    //family_name: 'Gump',
                    //given_name: 'Forrest',
                    ipaddr: '34.92.204.228',
                    //name: 'Forrest Gump',
                    oid: '90f7596b-88b6-4768-8204-8c476a73fe25',
                    rh: '0.AbcAqYXm1SM-2UKe-hXMXBzn2xNWhOMxA8BJnxH7amNCQtL8APU.',
                    //sub: 'KGceLH-HoENIN5H4jVwwaLI2rtpH-S2CTnJCHA0y0ak',
                    tid: 'd5e685a9-3e23-42d9-9efa-15cc5c1ce7db',
                    //unique_name: 'ForrestGump@Gitcoins.onmicrosoft.com',
                    //upn: 'ForrestGump@Gitcoins.onmicrosoft.com',
                    uti: 'YCuQilrDeEeCWYCghqobAA',
                    ver: '1.0'
                };
                user.account = account;
                user.expireTime = timestamp;
                user.email = account + "@gitcons.io";
                user.sub = account;
                //user.mail = user.email;
                //user.username = account;
                //user.name = account;
                //user.id = account;

                console.log(user);
                console.log(this.users.has(sign));
                this.users.set(sign, user);
                console.log(this.users.has(sign));
                console.log(this.users.get(sign));

                res.json(tokenResponse);

            } else {
                throw new Error('Verificaton Failure');
            }
        }
    }

    userinfo(options = {}) {
        return (req, res, next) => {

            console.log("hello from userinfo 1", req.headers);
            const authHeader = req.headers.authorization;
            console.log("hello from userinfo 2", authHeader);
            console.log(authHeader);

            let token = null;
            if (authHeader && authHeader.startsWith('Bearer')) {
                token = authHeader.split(' ')[1];
            }

            console.log(token);
            console.log(this.users.has(token))
            console.log(this.users.get(token));

            if (token && this.users.has(token)) {
                console.log("user info....");
                console.log(this.users.get(token));
                const user = this.users.get(token);
                //To check the expireTime in the user info
                if(Math.floor(Date.now()/1000) <= user.expireTime) {
                    console.log("user info....", user);
                    res.json(user);
                } else {
                    return res.status(400).json({ error: 'Out of date' });
                }
            } else {
                console("from eror....");
                throw new Error('No user info');
            }
        }
    }

    /**
     * Instantiates a new MSAL ConfidentialClientApplication object
     * @param msalConfig: MSAL Node Configuration object 
     * @returns 
     */
    getMsalInstance(msalConfig) {
        return new msal.ConfidentialClientApplication(msalConfig);
    }


    /**
     * Prepares the auth code request parameters and initiates the first leg of auth code flow
     * @param req: Express request object
     * @param res: Express response object
     * @param next: Express next function
     * @param authCodeUrlRequestParams: parameters for requesting an auth code url
     * @param authCodeRequestParams: parameters for requesting tokens using auth code
     */
    redirectToAuthCodeUrl(authCodeUrlRequestParams, authCodeRequestParams, msalInstance) {
        return async (req, res, next) => {
            // Generate PKCE Codes before starting the authorization flow
            const { verifier, challenge } = await this.cryptoProvider.generatePkceCodes();

            // Set generated PKCE codes and method as session vars
            req.session.pkceCodes = {
                challengeMethod: 'S256',
                verifier: verifier,
                challenge: challenge,
            };

            /**
             * By manipulating the request objects below before each request, we can obtain
             * auth artifacts with desired claims. For more information, visit:
             * https://azuread.github.io/microsoft-authentication-library-for-js/ref/modules/_azure_msal_node.html#authorizationurlrequest
             * https://azuread.github.io/microsoft-authentication-library-for-js/ref/modules/_azure_msal_node.html#authorizationcoderequest
             **/
            req.session.authCodeUrlRequest = {
                ...authCodeUrlRequestParams,
                responseMode: msal.ResponseMode.FORM_POST, // recommended for confidential clients
                codeChallenge: req.session.pkceCodes.challenge,
                codeChallengeMethod: req.session.pkceCodes.challengeMethod,
            };

            req.session.authCodeRequest = {
                ...authCodeRequestParams,
                code: '',
            };

            try {
                const authCodeUrlResponse = await msalInstance.getAuthCodeUrl(req.session.authCodeUrlRequest);
                res.redirect(authCodeUrlResponse);
            } catch (error) {
                next(error);
            }
        };
    }

    /**
     * Retrieves cloud discovery metadata from the /discovery/instance endpoint
     * @returns 
     */
    async getCloudDiscoveryMetadata(authority) {
        const endpoint = 'https://login.microsoftonline.com/common/discovery/instance';

        try {
            const response = await axios.get(endpoint, {
                params: {
                    'api-version': '1.1',
                    'authorization_endpoint': `${authority}/oauth2/v2.0/authorize`
                }
            });

            return await response.data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * Retrieves oidc metadata from the openid endpoint
     * @returns
     */
    async getAuthorityMetadata(authority) {
        const endpoint = `${authority}/v2.0/.well-known/openid-configuration`;

        try {
            const response = await axios.get(endpoint);
            return await response.data;
        } catch (error) {
            console.log(error);
        }
    }
}

const authProvider = new AuthProvider(msalConfig);

module.exports = authProvider;