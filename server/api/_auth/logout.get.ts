import { clearSessionCookie } from '@@/server/utils/oidc'

export default eventHandler((event) => {
  clearSessionCookie(event)
  return sendRedirect(event, '/')
})
