const msal = require('@azure/msal-node');
const axios = require('axios');
var path = require('path');
const { createCanvas, loadImage } = require('canvas');

const { msalConfig } = require('../authConfig');

const {
  encrypt,
  recoverPersonalSignature,
  recoverTypedSignature,
} = require('@metamask/eth-sig-util');


const { 
    MetaMaskSDK, 
    MetaMaskSDKOptions, 
    SDKProvider,
    PROVIDER_UPDATE_TYPE,
} = require('@metamask/sdk');
  
  
const {
    CommunicationLayerPreference,
    EventType,
    RemoteCommunication,
    ConnectionStatus,
} = require('@metamask/sdk-communication-layer');

const QRCode = require('qrcode');

const metamaskOptions = {
  shouldShimWeb3: false,
  //communicationServerUrl: 'http://192.168.50.10:4000',
  dappMetadata: {
    name: 'NodeJS example',
  },
  logging: {
    sdk: true,
    //sdk: false,
  },
  storage: {
    enabled: false
  },
  checkInstallationImmediately: false,
  // Optional: customize modal text
};

const METAMASK_CONNECT_BASE_URL = 'https://metamask.app.link/connect';
const METAMASK_DEEPLINK_BASE = 'metamask://connect';



const crypto = require('crypto');
const { time } = require('console');
const { toChecksumAddress } = require('ethereumjs-util');

class AuthProvider {
    msalConfig;
    cryptoProvider;
    users;
    MetaMaskSDKManager;
    

    constructor(msalConfig) {
        this.msalConfig = msalConfig
        this.cryptoProvider = new msal.CryptoProvider();
        this.users = new Map();
        this.MetaMaskSDKManager = new Map();
    };

    getQR(options = {}) {
        return async (req, res, next) => {

            const sdk = new MetaMaskSDK(metamaskOptions);
            //const accounts = await sdk.connect();

            sdk.on(EventType.AUTHORIZED, (data) => {
                console.log("sdk authorized .......................");
                console.log("authorized", data);
            });


            sdk.waitFor(EventType.PROVIDER_UPDATE).then(async (updateType) => { 

		     
                if (updateType == PROVIDER_UPDATE_TYPE.INITIALIZED) {
                    console.log("provider initialized .........................");
		    console.log(sdk.activeProvider);
		    const state = sdk.remoteConnection?.state;

			 state.connector.on(EventType.AUTHORIZED, async (data)=> {
						  console.log("connector authorized ........................");
						  console.log("connector sdk authorized", sdk.isAuthorized());
						  console.log("connector authorized", state.connector?.isAuthorized());
			    const provider = sdk.getProvider();
			    const from = provider.getSelectedAddress();
			    console.log(from);
			   const accounts = await sdk.activeProvider.request({
			    //method: RPC_METHODS.ETH_REQUESTACCOUNTS,
			    method: 'eth_requestAccounts',
			    params: [],
			  });
			    console.log(accounts);
			    this.MetaMaskSDKManager.set(accounts[0], sdk);

			});

		    const channelConfig1 = await state.connector.generateChannelIdConnect();
		    console.log("channelConfig1", channelConfig1);
		    const channelId = channelConfig1?.channelId ?? '';
		    const pubKey = channelConfig1?.pubKey?? '';
		    console.log("channelId", channelId);
		    console.log("pubKey", pubKey);

		    // if we are on desktop browser
		    const qrCodeOrigin = state.platformManager?.isSecure() ? '' : '&t=q';

		    const linkParams = encodeURI(
			  `channelId=${channelId}&v=2&comm=${
			    state.communicationLayerPreference ?? ''
			  }&pubkey=${pubKey}${qrCodeOrigin}`,
		    );

		    const qrcodeLink = `${
			   state.useDeeplink ? METAMASK_DEEPLINK_BASE : METAMASK_CONNECT_BASE_URL
		    }?${linkParams}`;
		    state.qrcodeLink = qrcodeLink;

		    //state.connector.disconnect();
		    console.log("qrcode", state.qrcodeLink);
		    //const qrCodeBuffer = await QRCode.toBuffer(state.qrcodeLink);
            
		    // Load the QR code image into a canvas
const FOX_IMAGE = `data:image/png;base64,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`;

        const qrCodeBuffer = await QRCode.toBuffer(state.qrcodeLink);

        // Load the QR code image into a canvas
        const canvas = createCanvas(500, 500);
        const ctx = canvas.getContext('2d');
        const qrImage = await loadImage(qrCodeBuffer);
        ctx.drawImage(qrImage, 0, 0, 500, 500);

        // Load the MetaMask icon
        //const metaMaskIconPath = path.join(__dirname, 'metamask-icon.png'); // Path to MetaMask icon
        const metaMaskIcon = await loadImage(FOX_IMAGE);

        // Calculate the size and position for the MetaMask icon
        const margin = 10;

	// Create a blank square in the QR image
	const squareSize = 100; // Size of the square
	const squareX = 200;   // X-coordinate of the square (centered)
	const squareY = 200;   // Y-coordinate of the square (centered)
	ctx.fillStyle = '#FFFFFF'; // Set fill color to white (or another background color)
	ctx.fillRect(squareX, squareY, squareSize, squareSize);
	ctx.drawImage(metaMaskIcon, squareX+margin, squareY+margin, squareSize-2*margin, squareSize-2*margin);

        // Convert the final image to a PNG buffer
        const finalBuffer = canvas.toBuffer('image/png');

        // Send the image as a response
	//state.connector.pause();
        res.writeHead(200, {
            'Content-Type': 'image/png',
        });
        res.end(finalBuffer);
        res.on('finish', () => {
	    //state.connector.resume();
            //const accounts = await sdk.connect();
	    //console.log(accounts);
        });
  		} else if (updateType == PROVIDER_UPDATE_TYPE.TERMINATE) {
                    console.log("provider terminate.........................");
                }
            });


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
