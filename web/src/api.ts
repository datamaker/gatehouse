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

export const api = {
  me: () => request<Me>('/api/me'),
  users: () => request<AdminUser[]>('/api/admin/users'),
  patchUser: (id: number, body: { is_active?: boolean; is_admin?: boolean }) =>
    request<AdminUser>(`/api/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  revokeSessions: (id: number) =>
    request<{ revoked: number }>(`/api/admin/users/${id}/sessions`, { method: 'DELETE' }),
  events: (email?: string) =>
    request<LoginEvent[]>(`/api/admin/events${email ? `?email=${encodeURIComponent(email)}` : ''}`),
};
