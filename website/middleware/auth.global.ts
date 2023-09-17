import { SESSION_COOKIE } from '@/constants'

export default defineNuxtRouteMiddleware((to) => {
  const sessionID = useCookie(SESSION_COOKIE)

  if (to.name !== 'auth' && !sessionID.value)
    return navigateTo('/auth')
})
