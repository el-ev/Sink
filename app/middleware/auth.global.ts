function isProtectedPath(path: string) {
  return path === '/new' || path === '/dashboard' || path.startsWith('/dashboard/')
}

function startOidc(path: string) {
  window.location.assign(`/api/_auth/login?redirect=${encodeURIComponent(path)}`)
}

export default defineNuxtRouteMiddleware(async (to) => {
  if (import.meta.server)
    return

  if (!isProtectedPath(to.path))
    return

  try {
    await $fetch('/api/_auth/session', {
      credentials: 'include',
    })
  }
  catch {
    startOidc(to.fullPath || to.path)
    return abortNavigation()
  }
})
