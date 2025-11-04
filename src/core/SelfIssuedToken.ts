import { SignJWT, exportJWK, calculateJwkThumbprint, GenerateKeyPairResult, KeyLike } from "jose"

export interface SelfIssuedTokenOptions {
  webid: string
  clientId: string
  dpopKeyPair: GenerateKeyPairResult<KeyLike>
  expiresIn?: number // seconds, default 3600
  issuer?: string // default "self-issued"
}

/**
 * Generate a self-issued access token for Solid.
 * The token is signed with the DPoP private key and bound to the DPoP public key.
 */
export const generateSelfIssuedAccessToken = async (options: SelfIssuedTokenOptions): Promise<string> => {
  const { webid, clientId, dpopKeyPair, expiresIn = 3600, issuer = "self-issued" } = options

  const jwkPublicKey = await exportJWK(dpopKeyPair.publicKey)
  const thumbprint = await calculateJwkThumbprint(jwkPublicKey)

  const now = Math.floor(Date.now() / 1000)
  const exp = now + expiresIn

  return new SignJWT({
    webid,
    client_id: clientId,
    cnf: { jkt: thumbprint }
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "JWT"
    })
    .setIssuer(issuer)
    .setSubject(webid)
    .setAudience("solid")
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(dpopKeyPair.privateKey)
}

/**
 * Renew a self-issued access token by generating a new one with updated expiration.
 */
export const renewSelfIssuedAccessToken = async (webid: string, options: Omit<SelfIssuedTokenOptions, 'webid'>): Promise<string> => {
  return generateSelfIssuedAccessToken({ ...options, webid })
}