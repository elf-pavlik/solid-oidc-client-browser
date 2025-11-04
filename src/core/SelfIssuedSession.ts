import { SessionCore, SessionOptions } from './Session'
import { generateSelfIssuedAccessToken, renewSelfIssuedAccessToken } from './SelfIssuedToken'
import { generateKeyPair, GenerateKeyPairResult, KeyLike } from 'jose'
import { DynamicRegistrationClientDetails, DereferencableIdClientDetails, TokenDetails } from './SessionInformation'

export interface SelfIssuedSessionOptions extends SessionOptions {
  webid: string
  clientId: string
}

export class SelfIssuedSession extends SessionCore {
  private webid: string
  private clientId: string
  private dpopKeyPair?: GenerateKeyPairResult<KeyLike>

  constructor(clientDetails?: DereferencableIdClientDetails | DynamicRegistrationClientDetails, sessionOptions?: SelfIssuedSessionOptions) {
    super(clientDetails, sessionOptions)
    if (!sessionOptions?.webid || !sessionOptions?.clientId) {
      throw new Error('webid and clientId must be provided in session options')
    }
    this.webid = sessionOptions.webid
    this.clientId = sessionOptions.clientId
  }

  /**
   * Login by generating a self-issued access token.
   * Ignores idp and redirect_uri parameters.
   */
  async login(idp: string, redirect_uri: string): Promise<void> {
    if (!this.webid || !this.clientId) {
      throw new Error('webid and clientId must be provided in session options')
    }

    // Generate DPoP key pair if not exists
    if (!this.dpopKeyPair) {
      this.dpopKeyPair = await generateKeyPair('ES256')
    }

    const accessToken = await generateSelfIssuedAccessToken({
      webid: this.webid,
      clientId: this.clientId,
      dpopKeyPair: this.dpopKeyPair,
      expiresIn: 3600 // 1 hour
    })

    const tokenDetails: TokenDetails = {
      access_token: accessToken,
      expires_in: 3600,
      dpop_key_pair: this.dpopKeyPair,
      token_type: 'DPoP'
    }

    await this.setTokenDetails(tokenDetails)

    // Persist to database if available
    if (this.database) {
      await this.database.init()
      await this.database.setItem('webid', this.webid)
      await this.database.setItem('client_id', this.clientId)
      await this.database.setItem('dpop_keypair', this.dpopKeyPair)
      this.database.close()
    }

    this.onSessionStateChange?.()
  }

  /**
   * Not applicable for self-issued, but implemented as no-op.
   */
  async handleRedirectFromLogin(): Promise<void> {
    // No-op
  }

  /**
   * Restore session by generating a new self-issued token.
   */
  async restore(): Promise<void> {
    if (!this.database) {
      throw new Error("Could not restore session: missing database. Provide database in sessionOption.")
    }

    if (this.refreshPromise) {
      return this.refreshPromise
    }

    this.refreshPromise = new Promise(async (resolve, reject) => {
      this.resolveRefresh = resolve
      this.rejectRefresh = reject

      try {
        await this.database!.init()
        const webid = await this.database!.getItem('webid') as string
        const clientId = await this.database!.getItem('client_id') as string
        const dpopKeyPair = await this.database!.getItem('dpop_keypair') as GenerateKeyPairResult<KeyLike>

        if (!webid || !clientId || !dpopKeyPair) {
          throw new Error('Missing session data in database')
        }

        const accessToken = await renewSelfIssuedAccessToken(webid, {
          clientId,
          dpopKeyPair,
          expiresIn: 3600
        })

        const tokenDetails: TokenDetails = {
          access_token: accessToken,
          expires_in: 3600,
          dpop_key_pair: dpopKeyPair,
          token_type: 'DPoP'
        }

        await this.setTokenDetails(tokenDetails)
        this.resolveRefresh!()
      } catch (error) {
        this.rejectRefresh!(error as Error)
      } finally {
        this.database!.close()
        this.clearRefreshPromise()
      }
    })

    return this.refreshPromise
  }
}