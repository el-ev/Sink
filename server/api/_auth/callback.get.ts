import {
  clearOidcHandshakeCookies,
  clearSessionCookie,
  discoverOidc,
  getOidcConfig,
  getOidcHandshake,
  getOidcRedirectUri,
  isEmailAllowed,
  setSessionCookie,
  tokenExchange,
  verifyIdToken,
} from '@@/server/utils/oidc'

export default eventHandler(async (event) => {
  const query = getQuery(event)
  const code = typeof query.code === 'string' ? query.code : ''
  const state = typeof query.state === 'string' ? query.state : ''

  const handshake = getOidcHandshake(event)
  clearOidcHandshakeCookies(event)

  if (!code || !state || !handshake.state || !handshake.verifier || state !== handshake.state) {
    throw createError({ statusCode: 401, statusMessage: 'Invalid OIDC callback state' })
  }

  const { issuer, clientId, clientSecret, allowedEmails, allowedDomains } = getOidcConfig(event)
  const redirectUri = getOidcRedirectUri(event)
  const discovery = await discoverOidc(issuer)

  const token = await tokenExchange({
    tokenEndpoint: discovery.token_endpoint,
    code,
    redirectUri,
    clientId,
    clientSecret,
    codeVerifier: handshake.verifier,
  })

  if (!token.id_token || typeof token.id_token !== 'string') {
    throw createError({ statusCode: 401, statusMessage: 'OIDC provider did not return id_token' })
  }

  const claims = await verifyIdToken(token.id_token, discovery, clientId, handshake.nonce)
  const email = typeof claims.email === 'string' ? claims.email : undefined

  if (!isEmailAllowed(allowedEmails, allowedDomains, email)) {
    clearSessionCookie(event)
    throw createError({ statusCode: 403, statusMessage: 'Email is not authorized' })
  }

  const now = Math.floor(Date.now() / 1000)
  const idTokenExp = typeof claims.exp === 'number' ? claims.exp : now + 60 * 60

  await setSessionCookie(event, {
    sub: String(claims.sub || ''),
    email,
    name: typeof claims.name === 'string' ? claims.name : undefined,
    picture: typeof claims.picture === 'string' ? claims.picture : undefined,
    iat: now,
    exp: Math.min(idTokenExp, now + 60 * 60 * 24 * 7),
  }, clientSecret)

  const redirectPath = handshake.redirectPath && handshake.redirectPath.startsWith('/')
    ? handshake.redirectPath
    : '/dashboard'

  return sendRedirect(event, redirectPath)
})
