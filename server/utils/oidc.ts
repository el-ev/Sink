import type { H3Event } from 'h3'

interface OidcDiscovery {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  userinfo_endpoint?: string
}

interface OidcSession {
  sub: string
  email?: string
  name?: string
  picture?: string
  exp: number
  iat: number
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function normalizeIssuer(issuer: string) {
  return issuer.endsWith('/') ? issuer.slice(0, -1) : issuer
}

function toBase64Url(bytes: Uint8Array) {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function fromBase64Url(input: string) {
  const b64 = input
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(input.length / 4) * 4, '=')
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function parseJwtPart(part: string) {
  return JSON.parse(decoder.decode(fromBase64Url(part)))
}

async function importHmacKey(secret: string) {
  return await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  )
}

async function signHmac(input: string, secret: string) {
  const key = await importHmacKey(secret)
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(input))
  return toBase64Url(new Uint8Array(signature))
}

async function verifyHmac(input: string, signature: string, secret: string) {
  const key = await importHmacKey(secret)
  return await crypto.subtle.verify('HMAC', key, fromBase64Url(signature), encoder.encode(input))
}

function isSafeRedirectPath(value: string | undefined | null) {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//')
}

function cookieOptions(event: H3Event, maxAgeSeconds: number) {
  return {
    path: '/',
    httpOnly: true,
    secure: getRequestURL(event).protocol === 'https:',
    sameSite: 'lax' as const,
    maxAge: maxAgeSeconds,
  }
}

export function getOidcConfig(event: H3Event) {
  const config = useRuntimeConfig(event)
  const issuer = config.oidcIssuer
  const clientId = config.oidcClientId
  const clientSecret = config.oidcClientSecret
  if (!issuer || !clientId || !clientSecret) {
    throw createError({
      statusCode: 500,
      statusMessage: 'OIDC is not configured',
    })
  }
  return {
    issuer,
    clientId,
    clientSecret,
    scopes: (config.oidcScopes || 'openid email profile').trim(),
    allowedEmails: (config.oidcAllowedEmails || '').split(',').map(s => s.trim()).filter(Boolean),
    allowedDomains: (config.oidcAllowedDomains || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean),
  }
}

export function randomUrlSafeString(byteLength: number) {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  return toBase64Url(bytes)
}

export async function pkceChallengeFromVerifier(verifier: string) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(verifier))
  return toBase64Url(new Uint8Array(digest))
}

export async function discoverOidc(issuer: string): Promise<OidcDiscovery> {
  const url = `${normalizeIssuer(issuer)}/.well-known/openid-configuration`
  const res = await fetch(url, { headers: { Accept: 'application/json' } })
  if (!res.ok) {
    throw createError({
      statusCode: 502,
      statusMessage: `OIDC discovery failed (${res.status})`,
    })
  }
  const data = await res.json() as Record<string, string>
  if (!data.issuer || !data.authorization_endpoint || !data.token_endpoint || !data.jwks_uri) {
    throw createError({
      statusCode: 502,
      statusMessage: 'OIDC discovery response missing required fields',
    })
  }
  return {
    issuer: data.issuer,
    authorization_endpoint: data.authorization_endpoint,
    token_endpoint: data.token_endpoint,
    jwks_uri: data.jwks_uri,
    userinfo_endpoint: data.userinfo_endpoint,
  }
}

async function verifyRs256(jwk: JsonWebKey, signed: string, signatureB64u: string) {
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  )
  return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, fromBase64Url(signatureB64u), encoder.encode(signed))
}

export async function verifyIdToken(idToken: string, discovery: OidcDiscovery, expectedAud: string, expectedNonce?: string) {
  const parts = idToken.split('.')
  if (parts.length !== 3) {
    throw createError({ statusCode: 401, statusMessage: 'Invalid id_token format' })
  }

  const headerB64u = parts[0]!
  const payloadB64u = parts[1]!
  const sigB64u = parts[2]!
  const header = parseJwtPart(headerB64u)
  const payload = parseJwtPart(payloadB64u)

  if (header.alg !== 'RS256') {
    throw createError({ statusCode: 401, statusMessage: 'Unsupported id_token algorithm' })
  }
  if (!header.kid) {
    throw createError({ statusCode: 401, statusMessage: 'id_token missing key id' })
  }

  if (payload.iss !== discovery.issuer) {
    throw createError({ statusCode: 401, statusMessage: 'id_token issuer mismatch' })
  }

  const audOk = Array.isArray(payload.aud)
    ? payload.aud.includes(expectedAud)
    : payload.aud === expectedAud

  if (!audOk) {
    throw createError({ statusCode: 401, statusMessage: 'id_token audience mismatch' })
  }

  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    throw createError({ statusCode: 401, statusMessage: 'id_token expired' })
  }

  if (expectedNonce && payload.nonce !== expectedNonce) {
    throw createError({ statusCode: 401, statusMessage: 'id_token nonce mismatch' })
  }

  const jwksRes = await fetch(discovery.jwks_uri, { headers: { Accept: 'application/json' } })
  if (!jwksRes.ok) {
    throw createError({ statusCode: 502, statusMessage: `JWKS fetch failed (${jwksRes.status})` })
  }

  const jwks = await jwksRes.json() as { keys?: JsonWebKey[] }
  const keys = Array.isArray(jwks.keys) ? jwks.keys : []
  const jwk = keys.find(k => (k as any).kid === header.kid)
  if (!jwk) {
    throw createError({ statusCode: 401, statusMessage: 'No matching JWK found' })
  }

  const signed = `${headerB64u}.${payloadB64u}`
  const ok = await verifyRs256(jwk, signed, sigB64u)
  if (!ok) {
    throw createError({ statusCode: 401, statusMessage: 'id_token signature invalid' })
  }

  return payload as Record<string, any>
}

export async function tokenExchange(params: {
  tokenEndpoint: string
  code: string
  redirectUri: string
  clientId: string
  clientSecret: string
  codeVerifier: string
}) {
  const body = new URLSearchParams()
  body.set('grant_type', 'authorization_code')
  body.set('code', params.code)
  body.set('redirect_uri', params.redirectUri)
  body.set('client_id', params.clientId)
  body.set('client_secret', params.clientSecret)
  body.set('code_verifier', params.codeVerifier)

  const basic = btoa(`${params.clientId}:${params.clientSecret}`)
  const res = await fetch(params.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${basic}`,
    },
    body,
  })

  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw createError({
      statusCode: 401,
      statusMessage: `Token exchange failed (${res.status}) ${text}`.trim(),
    })
  }

  return await res.json() as Record<string, any>
}

export function isEmailAllowed(allowedEmails: string[], allowedDomains: string[], email?: string | null) {
  if (!email)
    return false

  if (allowedEmails.length > 0)
    return allowedEmails.includes(email)

  if (allowedDomains.length > 0) {
    const at = email.lastIndexOf('@')
    const domain = at >= 0 ? email.slice(at + 1).toLowerCase() : ''
    return allowedDomains.includes(domain)
  }

  return true
}

export function getOidcRedirectUri(event: H3Event) {
  const url = getRequestURL(event)
  return `${url.origin}/api/_auth/callback`
}

export function setOidcHandshakeCookies(event: H3Event, data: {
  state: string
  verifier: string
  nonce: string
  redirectPath: string
}) {
  setCookie(event, 'sink_oidc_state', data.state, cookieOptions(event, 600))
  setCookie(event, 'sink_oidc_verifier', data.verifier, cookieOptions(event, 600))
  setCookie(event, 'sink_oidc_nonce', data.nonce, cookieOptions(event, 600))
  setCookie(event, 'sink_oidc_redirect', data.redirectPath, cookieOptions(event, 600))
}

export function clearOidcHandshakeCookies(event: H3Event) {
  deleteCookie(event, 'sink_oidc_state', { path: '/' })
  deleteCookie(event, 'sink_oidc_verifier', { path: '/' })
  deleteCookie(event, 'sink_oidc_nonce', { path: '/' })
  deleteCookie(event, 'sink_oidc_redirect', { path: '/' })
}

export function getOidcHandshake(event: H3Event) {
  return {
    state: getCookie(event, 'sink_oidc_state'),
    verifier: getCookie(event, 'sink_oidc_verifier'),
    nonce: getCookie(event, 'sink_oidc_nonce'),
    redirectPath: getCookie(event, 'sink_oidc_redirect'),
  }
}

export async function setSessionCookie(event: H3Event, session: OidcSession, secret: string) {
  const payload = toBase64Url(encoder.encode(JSON.stringify(session)))
  const signature = await signHmac(payload, secret)
  setCookie(event, 'sink_auth_session', `${payload}.${signature}`, cookieOptions(event, 60 * 60 * 24 * 7))
}

export function clearSessionCookie(event: H3Event) {
  deleteCookie(event, 'sink_auth_session', { path: '/' })
}

export async function getSessionFromCookie(event: H3Event, secret: string): Promise<OidcSession | null> {
  const cookie = getCookie(event, 'sink_auth_session')
  if (!cookie)
    return null

  const [payload, signature] = cookie.split('.')
  if (!payload || !signature)
    return null

  const valid = await verifyHmac(payload, signature, secret)
  if (!valid)
    return null

  try {
    const session = JSON.parse(decoder.decode(fromBase64Url(payload))) as OidcSession
    if (!session.exp || session.exp <= Math.floor(Date.now() / 1000))
      return null
    return session
  }
  catch {
    return null
  }
}

export function getRequestedRedirectPath(event: H3Event, fallback = '/dashboard') {
  const value = getQuery(event).redirect
  if (typeof value !== 'string')
    return fallback
  return isSafeRedirectPath(value) ? value : fallback
}

export function isProtectedPagePath(path: string) {
  return path === '/new' || path === '/dashboard' || path.startsWith('/dashboard/')
}

export function getFullPath(event: H3Event) {
  const requestUrl = getRequestURL(event)
  return `${requestUrl.pathname}${requestUrl.search}`
}
