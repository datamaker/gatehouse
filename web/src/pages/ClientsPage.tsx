import { useEffect, useState } from 'react';
import { api, type OidcClient } from '../api';

export function ClientsPage() {
  const [clients, setClients] = useState<OidcClient[]>([]);
  const [error, setError] = useState('');
  const [created, setCreated] = useState<OidcClient | null>(null);
  const [form, setForm] = useState({ client_id: '', name: '', redirect_uris: '' });

  const reload = () => api.clients().then(setClients).catch((e) => setError(e.message));
  useEffect(() => {
    reload();
  }, []);

  const create = async () => {
    setError('');
    try {
      const c = await api.createClient({
        client_id: form.client_id.trim(),
        name: form.name.trim(),
        redirect_uris: form.redirect_uris.split(/[\n,]/).map((s) => s.trim()).filter(Boolean),
      });
      setCreated(c);
      setForm({ client_id: '', name: '', redirect_uris: '' });
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const remove = async (c: OidcClient) => {
    if (!window.confirm(`${c.name} (${c.client_id}) 클라이언트를 삭제할까요? 이 앱의 SSO 로그인이 즉시 중단됩니다.`)) return;
    setError('');
    try {
      await api.deleteClient(c.id);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <main>
      {error && <div className="error">{error}</div>}
      {created && (
        <div className="secret-box">
          <strong>{created.name}</strong> 클라이언트가 생성됐습니다. secret은 지금만 표시됩니다:
          <code>{created.client_secret}</code>
          <button className="ghost small" onClick={() => setCreated(null)}>닫기</button>
        </div>
      )}

      <div className="client-form">
        <input
          placeholder="client_id (예: lookout)"
          value={form.client_id}
          onChange={(e) => setForm({ ...form, client_id: e.target.value })}
        />
        <input
          placeholder="이름 (예: Lookout)"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
        />
        <input
          placeholder="redirect URI (comma로 여러 개)"
          value={form.redirect_uris}
          onChange={(e) => setForm({ ...form, redirect_uris: e.target.value })}
        />
        <button className="ghost" disabled={!form.client_id || !form.name || !form.redirect_uris} onClick={create}>
          추가
        </button>
      </div>

      <table>
        <thead>
          <tr>
            <th>이름</th>
            <th>client_id</th>
            <th>redirect URIs</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {clients.map((c) => (
            <tr key={c.id}>
              <td>{c.name}</td>
              <td><code>{c.client_id}</code></td>
              <td className="small muted">{c.redirect_uris.join(', ')}</td>
              <td>
                <button className="ghost small" onClick={() => remove(c)}>삭제</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {clients.length === 0 && <p className="muted center">등록된 OIDC 클라이언트가 없습니다.</p>}
      <p className="muted small">
        issuer: <code>https://auth.datasee.co.kr/oidc</code> · discovery:{' '}
        <code>/oidc/.well-known/openid-configuration</code> · scopes: openid email profile · PKCE 필수
      </p>
    </main>
  );
}
