export function isAuthenticated(): boolean {
  const sessionID = useCookie('sessionID')

  return !!sessionID.value
}
