import { getOidcConfig, getSessionFromCookie } from '@@/server/utils/oidc'

export default eventHandler(async (event) => {
  const { clientSecret } = getOidcConfig(event)
  const session = await getSessionFromCookie(event, clientSecret)

  if (!session) {
    throw createError({ statusCode: 401, statusMessage: 'Unauthorized' })
  }

  return {
    sub: session.sub,
    email: session.email,
    name: session.name,
    picture: session.picture,
    exp: session.exp,
  }
})
