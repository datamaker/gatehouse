import { useEffect, useState } from 'react';
import { api, type AdminUser, type Me } from '../api';

function fmt(ts: string | null): string {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('ko-KR', { dateStyle: 'short', timeStyle: 'short' });
}

export function UsersPage({ me }: { me: Me }) {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [error, setError] = useState('');

  const reload = () => api.users().then(setUsers).catch((e) => setError(e.message));
  useEffect(() => {
    reload();
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

  return (
    <main>
      {error && <div className="error">{error}</div>}
      <table>
        <thead>
          <tr>
            <th>사용자</th>
            <th>도메인</th>
            <th>마지막 로그인</th>
            <th>세션</th>
            <th>상태</th>
            <th>권한</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id} className={u.is_active ? '' : 'inactive'}>
              <td className="cell-primary">
                <div className="user-cell">
                  {u.picture && <img src={u.picture} alt="" referrerPolicy="no-referrer" />}
                  <div>
                    <div>{u.name || '—'}</div>
                    <div className="muted small">{u.email}</div>
                  </div>
                </div>
              </td>
              <td data-label="도메인">{u.hd}</td>
              <td data-label="마지막 로그인">{fmt(u.last_login_at)}</td>
              <td data-label="세션">{u.active_sessions}</td>
              <td data-label="상태">
                <button
                  className={u.is_active ? 'pill on' : 'pill off'}
                  disabled={u.id === me.id}
                  title={u.id === me.id ? '자기 자신은 비활성화할 수 없습니다' : ''}
                  onClick={() => act(() => api.patchUser(u.id, { is_active: !u.is_active }))}
                >
                  {u.is_active ? '활성' : '비활성'}
                </button>
              </td>
              <td data-label="권한">
                <button
                  className={u.is_admin ? 'pill on' : 'pill'}
                  disabled={u.id === me.id}
                  title={u.id === me.id ? '자기 자신의 권한은 바꿀 수 없습니다' : ''}
                  onClick={() => act(() => api.patchUser(u.id, { is_admin: !u.is_admin }))}
                >
                  {u.is_admin ? 'admin' : 'member'}
                </button>
              </td>
              <td>
                <button
                  className="ghost small"
                  disabled={u.active_sessions === 0}
                  onClick={() => act(() => api.revokeSessions(u.id))}
                >
                  세션 종료
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {users.length === 0 && <p className="muted center">아직 로그인한 사용자가 없습니다.</p>}
    </main>
  );
}
