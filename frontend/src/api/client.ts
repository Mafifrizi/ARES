// Compatibility facade: existing feature imports continue to use this stable public API.
export {
  apiBlobRequest,
  apiRequest,
  ApiError,
  bootstrapBrowserCsrf,
  browserMutationRequest,
  refreshAccessToken,
  withRefreshCookieLock
} from "./http";
export { api, buildModuleRunPayload, campaignEventsPath, login, logout, logoutAll } from "./endpoints";
export {
  beginIdentityTransition,
  browserCoordinationAvailable,
  captureSession,
  clearTokens,
  getAccessToken,
  invalidateSession,
  isSessionCurrent,
  readCoordinationRecord,
  subscribeToSessionInvalidation,
  setAccessToken
} from "./session";
