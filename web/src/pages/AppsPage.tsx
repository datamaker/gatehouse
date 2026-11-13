import { useEffect, useState } from 'react';
import { api, type AdminUser, type AppPolicy } from '../api';

/**
 * 앱별 접근 정책. 기본은 "전체 허용"(활성 사용자 전원)이고, "제한"으로 바꾸면 허용 목록의 사용자만 들어갈 수 있다.
 * 앱 키는 forward-auth 호스트(예: vault.datasee.co.kr) 또는 oidc:<client_id>.
 */
export function AppsPage() {
  const [apps, setApps] = useState<AppPolicy[]>([]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [newKey, setNewKey] = useState('');
  const [error, setError] = useState('');

  const reload = () => api.apps().then(setApps).catch((e) => setError(e.message));
  useEffect(() => {
    reload();
    api.users().then(setUsers).catch((e) => setError(e.message));
  }, []);

  const act = async (fn: () => Promise<unknown>) => {
    setError('');
    try {
      await fn();
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const toggleMode = (a: AppPolicy) => {
    const next = a.mode === 'restricted' ? 'all' : 'restricted';
    if (next === 'restricted') {
      const msg =
        a.users.length === 0
          ? `${a.app_key} 을(를) 제한하면 허용 목록이 비어 있어 아무도 들어갈 수 없게 됩니다. 계속할까요?`
          : `${a.app_key} 을(를) 허용 목록 ${a.users.length}명만 쓸 수 있게 제한할까요?`;
      if (!window.confirm(msg)) return;
    }
    act(() => api.setAppPolicy(a.app_key, { mode: next }));
  };

  const addApp = () => {
    const key = newKey.trim().toLowerCase();
    if (!key) return;
    // 정책 행만 만들어 둔다(전체 허용). 목록을 채운 뒤 제한으로 바꾼다.
    act(async () => {
      await api.setAppPolicy(key, { mode: 'all' });
      setNewKey('');
      setOpen(key);
    });
  };

  return (
    <main>
      {error && <div className="error">{error}</div>}
      <div className="card zt-config">
        <div className="muted small">
          기본은 <b>전체 허용</b>(활성 사용자 전원)입니다. <b>제한</b>으로 바꾸면 허용 목록의 사용자만 접근할 수 있고, 나머지는 403
          안내 페이지를 봅니다. 변경은 바로 적용됩니다. 목록에는 최근 30일 동안 접속 판정에 나온 호스트와 OIDC 클라이언트가 보입니다.
        </div>
      </div>
      <div className="toolbar">
        <input
          className="filter"
          placeholder="앱 추가: 호스트(vault.datasee.co.kr) 또는 oidc:client_id"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && addApp()}
        />
        <button className="ghost" disabled={!newKey.trim()} onClick={addApp}>
          추가
        </button>
      </div>
      <table>
        <thead>
          <tr>
            <th>앱</th>
            <th>종류</th>
            <th>접근</th>
            <th>허용 사용자</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {apps.map((a) => {
            const allowed = new Set(a.users.map((u) => u.id));
            const candidates = users.filter((u) => u.is_active && !allowed.has(u.id));
            return (
              <tr key={a.app_key} className={a.mode === 'restricted' ? '' : 'app-open'}>
                <td className="cell-primary">
                  <div>{a.name || a.app_key}</div>
                  {a.name && <div className="muted small">{a.app_key}</div>}
                </td>
                <td data-label="종류">{a.kind === 'oidc' ? 'OIDC' : 'forward-auth'}</td>
                <td data-label="접근">
                  <button className={a.mode === 'restricted' ? 'pill off' : 'pill on'} onClick={() => toggleMode(a)}>
                    {a.mode === 'restricted' ? '제한' : '전체 허용'}
                  </button>
                </td>
                <td data-label="허용 사용자">
                  {open === a.app_key ? (
                    <div className="app-users">
                      {a.users.map((u) => (
                        <span key={u.id} className={`chip ${u.is_active ? '' : 'inactive'}`}>
                          {u.email}
                          <button
                            title="허용 목록에서 제거"
                            onClick={() => act(() => api.removeAppUser(a.app_key, u.id))}
                          >
                            ×
                          </button>
                        </span>
                      ))}
                      <select
                        value=""
                        onChange={(e) => {
                          const id = parseInt(e.target.value, 10);
                          if (id) act(() => api.addAppUser(a.app_key, id));
                        }}
                      >
                        <option value="">사용자 추가…</option>
                        {candidates.map((u) => (
                          <option key={u.id} value={u.id}>
                            {u.email}
                            {u.name ? ` (${u.name})` : ''}
                          </option>
                        ))}
                      </select>
                    </div>
                  ) : (
                    <span className={a.mode === 'restricted' ? '' : 'muted'}>
                      {a.users.length}명{a.mode !== 'restricted' && a.users.length > 0 && ' (제한 시 적용)'}
                    </span>
                  )}
                </td>
                <td>
                  <button className="ghost small" onClick={() => setOpen(open === a.app_key ? null : a.app_key)}>
                    {open === a.app_key ? '닫기' : '사용자 관리'}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {apps.length === 0 && <p className="muted center">알려진 앱이 없습니다. 위에서 호스트를 직접 추가하세요.</p>}
    </main>
  );
}
