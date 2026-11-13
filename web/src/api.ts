export interface Me {
  id: number;
  email: string;
  name: string;
  hd: string;
  picture: string | null;
  is_admin: boolean;
}

export interface AdminUser {
  id: number;
  email: string;
  name: string;
  hd: string;
  picture: string | null;
  is_active: boolean;
  is_admin: boolean;
  created_at: string;
  last_login_at: string | null;
  active_sessions: number;
}

export interface LoginEvent {
  id: number;
  email: string;
  event: 'login' | 'logout' | 'denied';
  detail: string | null;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
    ...init,
  });
  if (res.status === 401) {
    window.location.href = `/login?rd=${encodeURIComponent(window.location.href)}`;
    throw new Error('redirecting to login');
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as { error?: string } | null;
    throw new Error(body?.error ?? `${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export interface OidcClient {
  id: number;
  client_id: string;
  name: string;
  redirect_uris: string[];
  grant_types: string[];
  token_endpoint_auth_method: string;
  created_at: string;
  client_secret?: string;
}

export interface ZtConfig {
  mode: 'off' | 'monitor' | 'enforce';
  ward_url: string;
  ward_public_url: string;
  secret_set: boolean;
  fail_open: boolean;
  cache_sec: number;
  timeout_ms: number;
  exempt_emails: string[];
  exempt_hosts: string[];
  enforce_emails: string[];
  enforce_count: number;
  oidc_exempt_clients: string[];
}

export interface AdminEvent {
  id: number;
  actor_email: string;
  action: string;
  target: string;
  detail: Record<string, unknown>;
  ip: string | null;
  created_at: string;
}

export interface AppUser {
  id: number;
  email: string;
  name: string;
  is_active: boolean;
}

export interface AppPolicy {
  app_key: string;
  kind: 'host' | 'oidc';
  name: string;
  mode: 'all' | 'restricted';
  note: string | null;
  updated_at: string | null;
  users: AppUser[];
}

export interface ZtCheck {
  id: number;
  email: string;
  host: string;
  ip: string;
  verdict: string;
  device_id: string | null;
  device_hostname: string | null;
  mode: string;
  allowed: boolean;
  error: string | null;
  created_at: string;
}

export const api = {
  me: () => request<Me>('/api/me'),
  clients: () => request<OidcClient[]>('/api/admin/clients'),
  createClient: (body: {
    client_id: string;
    name: string;
    redirect_uris: string[];
    grant_types?: string[];
    token_endpoint_auth_method?: string;
  }) =>
    request<OidcClient>('/api/admin/clients', { method: 'POST', body: JSON.stringify(body) }),
  deleteClient: (id: number) =>
    request<{ deleted: boolean }>(`/api/admin/clients/${id}`, { method: 'DELETE' }),
  users: () => request<AdminUser[]>('/api/admin/users'),
  patchUser: (id: number, body: { is_active?: boolean; is_admin?: boolean }) =>
    request<AdminUser>(`/api/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  revokeSessions: (id: number) =>
    request<{ revoked: number }>(`/api/admin/users/${id}/sessions`, { method: 'DELETE' }),
  events: (email?: string) =>
    request<LoginEvent[]>(`/api/admin/events${email ? `?email=${encodeURIComponent(email)}` : ''}`),
  adminEvents: (q?: string) =>
    request<AdminEvent[]>(`/api/admin/audit${q ? `?q=${encodeURIComponent(q)}` : ''}`),
  apps: () => request<AppPolicy[]>('/api/admin/apps'),
  setAppPolicy: (key: string, body: { mode: 'all' | 'restricted'; note?: string | null }) =>
    request<unknown>(`/api/admin/apps/${encodeURIComponent(key)}`, { method: 'PUT', body: JSON.stringify(body) }),
  addAppUser: (key: string, userId: number) =>
    request<{ added: boolean }>(`/api/admin/apps/${encodeURIComponent(key)}/users/${userId}`, { method: 'PUT' }),
  removeAppUser: (key: string, userId: number) =>
    request<{ removed: boolean }>(`/api/admin/apps/${encodeURIComponent(key)}/users/${userId}`, { method: 'DELETE' }),
  ztConfig: () => request<ZtConfig>('/api/admin/zt/config'),
  ztChecks: (email?: string, deniedOnly = false) => {
    const q = new URLSearchParams();
    if (email) q.set('email', email);
    if (deniedOnly) q.set('denied', '1');
    const qs = q.toString();
    return request<ZtCheck[]>(`/api/admin/zt/checks${qs ? `?${qs}` : ''}`);
  },
};
