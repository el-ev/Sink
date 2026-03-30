import {
  discoverOidc,
  getOidcConfig,
  getOidcRedirectUri,
  getRequestedRedirectPath,
  pkceChallengeFromVerifier,
  randomUrlSafeString,
  setOidcHandshakeCookies,
} from '@@/server/utils/oidc'

export default eventHandler(async (event) => {
  const { issuer, clientId, scopes } = getOidcConfig(event)
  const discovery = await discoverOidc(issuer)

  const state = randomUrlSafeString(32)
  const verifier = randomUrlSafeString(64)
  const nonce = randomUrlSafeString(32)
  const codeChallenge = await pkceChallengeFromVerifier(verifier)
  const redirectPath = getRequestedRedirectPath(event)
  const redirectUri = getOidcRedirectUri(event)

  setOidcHandshakeCookies(event, { state, verifier, nonce, redirectPath })

  const authUrl = new URL(discovery.authorization_endpoint)
  authUrl.searchParams.set('response_type', 'code')
  authUrl.searchParams.set('client_id', clientId)
  authUrl.searchParams.set('redirect_uri', redirectUri)
  authUrl.searchParams.set('scope', scopes)
  authUrl.searchParams.set('state', state)
  authUrl.searchParams.set('nonce', nonce)
  authUrl.searchParams.set('code_challenge', codeChallenge)
  authUrl.searchParams.set('code_challenge_method', 'S256')

  return sendRedirect(event, authUrl.toString())
})
