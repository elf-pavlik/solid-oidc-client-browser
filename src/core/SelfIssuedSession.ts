import { SignJWT, generateKeyPair, decodeJwt } from "jose";
import { SessionCore, SessionOptions } from "./Session";
import { DereferencableIdClientDetails, DynamicRegistrationClientDetails, TokenDetails } from "./SessionInformation";

export interface SelfIssuedSessionOptions extends SessionOptions {
  /**
   * Time in seconds before token expiration when proactive renewal should occur
   * Default: 300 seconds (5 minutes)
   */
  proactiveRenewalThreshold?: number;
  
  /**
   * Callback function called when a proactive token renewal is performed
   */
  onProactiveRenewal?: () => void;
}

/**
 * SelfIssuedSession extends SessionCore to provide self-issued access token functionality.
 * Instead of redirecting to an IDP, it generates its own access tokens.
 */
export class SelfIssuedSession extends SessionCore {
  private proactiveRenewalThreshold: number;
  private proactiveRenewalTimeout?: any;
  private onProactiveRenewal?: () => void;

  constructor(
    clientDetails?: DereferencableIdClientDetails | DynamicRegistrationClientDetails,
    sessionOptions?: SelfIssuedSessionOptions
  ) {
    super(clientDetails, sessionOptions);
    this.proactiveRenewalThreshold = sessionOptions?.proactiveRenewalThreshold || 300; // 5 minutes default
    this.onProactiveRenewal = sessionOptions?.onProactiveRenewal;
  }

  /**
   * Creates a self-issued access token for login instead of redirecting to an IDP.
   * This generates a self-signed JWT that acts as an access token.
   */
  async login(webId: string): Promise<void> {
    // Generate a new key pair for DPoP
    const keyPair = await generateKeyPair("ES256");
    
    // Set expiration time (1 hour from now)
    const now = Math.floor(Date.now() / 1000);
    const exp = now + 3600; // 1 hour in seconds
    
    // Create a self-issued access token
    const accessToken = await new SignJWT({
      webid: webId,
      client_id: webId, // Using WebID as client_id for self-issued tokens
      aud: "solid", // Audience for Solid ecosystem
      exp: exp, // Expiration time
      iat: now, // Issued at
      iss: webId, // Self-issued, so issuer is the WebID
      sub: webId, // Subject
    })
      .setProtectedHeader({ alg: "ES256", typ: "JWT" })
      .sign(keyPair.privateKey);
    
    // Create token details
    const tokenDetails: TokenDetails = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600, // 1 hour in seconds
      dpop_key_pair: keyPair,
    };
    
    // Set token details in the session
    await this.setTokenDetails(tokenDetails);
    
    // Schedule proactive renewal
    this.scheduleProactiveRenewal(3600);
    
    // Call the session state change callback
    this.onSessionStateChange?.();
  }

  /**
   * Override handleRedirectFromLogin to do nothing since we don't redirect for self-issued tokens
   */
  async handleRedirectFromLogin(): Promise<void> {
    // No redirect handling needed for self-issued tokens
    return Promise.resolve();
  }

  /**
   * Override restore to regenerate token instead of using refresh token grant
   */
  async restore(): Promise<void> {
    // For self-issued tokens, we simply regenerate a new token
    // In a real implementation, you might want to check if we have stored credentials
    // and use those to generate a new token
    
    // Get current WebID if we have one
    const webId = this.webId;
    if (!webId) {
      throw new Error("No WebID available to restore session");
    }
    
    // Generate a new token for the same WebID
    await this.login(webId);
  }

  /**
   * Override logout to clear proactive renewal timeout
   */
  async logout(): Promise<void> {
    // Clear any scheduled proactive renewal
    if (this.proactiveRenewalTimeout) {
      clearTimeout(this.proactiveRenewalTimeout);
      this.proactiveRenewalTimeout = undefined;
    }
    
    // Call parent logout
    await super.logout();
  }

  /**
   * Schedule proactive token renewal before expiration
   */
  private scheduleProactiveRenewal(expiresIn: number): void {
    // Clear any existing timeout
    if (this.proactiveRenewalTimeout) {
      clearTimeout(this.proactiveRenewalTimeout);
    }

    // Schedule renewal before token expires
    const renewalTime = (expiresIn - this.proactiveRenewalThreshold) * 1000;
    
    if (renewalTime > 0) {
      this.proactiveRenewalTimeout = setTimeout(async () => {
        try {
          // Get current WebID
          const webId = this.webId;
          if (webId) {
            // Generate new token
            await this.login(webId);
            
            // Call the proactive renewal callback
            this.onProactiveRenewal?.();
          }
        } catch (error) {
          console.error("Failed to proactively renew token:", error);
        }
      }, renewalTime);
    }
  }

  /**
   * Override setTokenDetails to schedule proactive renewal
   */
  protected async setTokenDetails(tokenDetails: TokenDetails) {
    // Call parent implementation
    await super.setTokenDetails(tokenDetails);
    
    // Schedule proactive renewal
    const expiresIn = tokenDetails.expires_in || 3600;
    this.scheduleProactiveRenewal(expiresIn);
  }
}