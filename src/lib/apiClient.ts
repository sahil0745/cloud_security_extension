export const API_BASE_URL =
  (import.meta as any).env?.VITE_FASTAPI_BASE_URL || 'http://127.0.0.1:8000';

const TOKEN_KEY = 'cloudsec_jwt_token';
const REFRESH_TOKEN_KEY = 'cloudsec_refresh_token';

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

export class ApiError extends Error {
  status: number;
  payload: unknown;

  constructor(message: string, status: number, payload: unknown = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.payload = payload;
  }
}

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setStoredToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function getStoredRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setStoredRefreshToken(token: string) {
  localStorage.setItem(REFRESH_TOKEN_KEY, token);
}

export function clearStoredToken() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
}

let refreshInFlight: Promise<string | null> | null = null;

async function refreshAccessToken(): Promise<string | null> {
  const currentRefreshToken = getStoredRefreshToken();
  if (!currentRefreshToken) {
    return null;
  }

  const res = await fetch(buildUrl('/api/auth/refresh'), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${currentRefreshToken}`,
    },
  });

  const payload = await parsePayload(res);
  if (!res.ok) {
    throw new ApiError(`Refresh failed with status ${res.status}`, res.status, payload);
  }

  const tokenResponse = payload as LoginResponse;
  if (!tokenResponse.access_token || !tokenResponse.refresh_token) {
    throw new ApiError('Refresh response missing tokens', 500, payload);
  }

  setStoredToken(tokenResponse.access_token);
  setStoredRefreshToken(tokenResponse.refresh_token);
  return tokenResponse.access_token;
}

async function getRefreshedTokenWithSingleFlight(): Promise<string | null> {
  if (!refreshInFlight) {
    refreshInFlight = refreshAccessToken()
      .catch(() => null)
      .finally(() => {
        refreshInFlight = null;
      });
  }
  return refreshInFlight;
}

function buildUrl(path: string): string {
  if (path.startsWith('http://') || path.startsWith('https://')) {
    return path;
  }
  return `${API_BASE_URL}${path.startsWith('/') ? '' : '/'}${path}`;
}

async function parsePayload(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }
  if (contentType.includes('text/')) {
    return response.text();
  }
  return response.arrayBuffer();
}

async function request<T>(path: string, method: HttpMethod, body?: unknown, options: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers = new Headers(options.headers || {});
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  if (body !== undefined && !(body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  const doFetch = (currentHeaders: Headers) =>
    fetch(buildUrl(path), {
      ...options,
      method,
      headers: currentHeaders,
      body: body === undefined ? undefined : body instanceof FormData ? body : JSON.stringify(body),
    });

  let res = await doFetch(headers);
  if (res.status === 401) {
    const refreshedToken = await getRefreshedTokenWithSingleFlight();
    if (refreshedToken) {
      const retryHeaders = new Headers(options.headers || {});
      retryHeaders.set('Authorization', `Bearer ${refreshedToken}`);
      if (body !== undefined && !(body instanceof FormData)) {
        retryHeaders.set('Content-Type', 'application/json');
      }
      res = await doFetch(retryHeaders);
    }
  }

  const payload = await parsePayload(res);

  if (!res.ok) {
    if (res.status === 401) {
      clearStoredToken();
      window.dispatchEvent(new CustomEvent('auth:expired'));
    }
    throw new ApiError(`Request failed with status ${res.status}`, res.status, payload);
  }

  return payload as T;
}

async function download(path: string, filename: string): Promise<void> {
  const token = getStoredToken();
  const headers = new Headers();
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const res = await fetch(buildUrl(path), { method: 'GET', headers });
  if (!res.ok) {
    const payload = await parsePayload(res);
    throw new ApiError(`Download failed with status ${res.status}`, res.status, payload);
  }

  const blob = await res.blob();
  const blobUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(blobUrl);
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export const apiClient = {
  get: <T>(path: string, options?: RequestInit) => request<T>(path, 'GET', undefined, options),
  post: <T>(path: string, body?: unknown, options?: RequestInit) => request<T>(path, 'POST', body, options),
  put: <T>(path: string, body?: unknown, options?: RequestInit) => request<T>(path, 'PUT', body, options),
  del: <T>(path: string, options?: RequestInit) => request<T>(path, 'DELETE', undefined, options),
  download,
  login: async (username: string, password: string): Promise<LoginResponse> => {
    const form = new URLSearchParams();
    form.set('username', username);
    form.set('password', password);

    const res = await fetch(buildUrl('/api/auth/login'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });

    const payload = await parsePayload(res);
    if (!res.ok) {
      throw new ApiError(`Login failed with status ${res.status}`, res.status, payload);
    }
    const login = payload as LoginResponse;
    if (!login.access_token || !login.refresh_token) {
      throw new ApiError('Login response missing tokens', res.status, payload);
    }
    setStoredToken(login.access_token);
    setStoredRefreshToken(login.refresh_token);
    return payload as LoginResponse;
  },
};
