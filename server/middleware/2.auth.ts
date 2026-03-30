import {
  getFullPath,
  getOidcConfig,
  getSessionFromCookie,
  isProtectedPagePath,
} from '@@/server/utils/oidc'

export default eventHandler(async (event) => {
  const isApi = event.path.startsWith('/api/')
  const isAuthApi = event.path.startsWith('/api/_auth/')
  const isProtectedApi = isApi && !isAuthApi
  const isProtectedPage = !isApi && isProtectedPagePath(event.path)

  if (!isProtectedApi && !isProtectedPage)
    return

  const { clientSecret } = getOidcConfig(event)
  const session = await getSessionFromCookie(event, clientSecret)

  if (session)
    return

  if (isProtectedApi) {
    throw createError({
      statusCode: 401,
      statusMessage: 'Unauthorized',
    })
  }

  return sendRedirect(event, `/api/_auth/login?redirect=${encodeURIComponent(getFullPath(event))}`)
})
