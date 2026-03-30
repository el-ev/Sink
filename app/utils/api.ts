import { defu } from 'defu'
import { toast } from 'vue-sonner'

function isProtectedPath(path: string) {
  return path === '/new' || path === '/dashboard' || path.startsWith('/dashboard/')
}

function redirectToLogin(path: string) {
  window.location.assign(`/api/_auth/login?redirect=${encodeURIComponent(path)}`)
}

export function useAPI(api: string, options?: object): Promise<unknown> {
  return $fetch(api, defu(options || {}, {})).catch((error) => {
    if (error?.status === 401 && import.meta.client) {
      const path = window.location.pathname + window.location.search
      if (isProtectedPath(window.location.pathname)) {
        redirectToLogin(path)
      }
    }
    if (error?.data?.statusMessage) {
      toast(error?.data?.statusMessage)
    }
    return Promise.reject(error)
  })
}
