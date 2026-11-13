import { useEffect, useState } from 'react';
import { api, type AdminEvent, type LoginEvent } from '../api';

const LABEL: Record<LoginEvent['event'], string> = {
  login: '로그인',
  logout: '로그아웃',
  denied: '거부',
};

const ACTION: Record<string, string> = {
  'user.activate': '사용자 활성화',
  'user.deactivate': '사용자 비활성화',
  'user.role': '권한 변경',
  'user.sessions.revoke': '세션 종료',
  'client.create': 'OIDC 클라이언트 생성',
  'client.update': 'OIDC 클라이언트 수정',
  'client.delete': 'OIDC 클라이언트 삭제',
  'app.policy': '앱 접근 모드 변경',
  'app.user.add': '앱 허용 사용자 추가',
  'app.user.remove': '앱 허용 사용자 제거',
};

type View = 'login' | 'admin';

const fmt = (ts: string) => new Date(ts).toLocaleString('ko-KR', { dateStyle: 'short', timeStyle: 'medium' });

export function AuditPage() {
  const [view, setView] = useState<View>('login');
  const [events, setEvents] = useState<LoginEvent[]>([]);
  const [adminEvents, setAdminEvents] = useState<AdminEvent[]>([]);
  const [filter, setFilter] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    const t = setTimeout(() => {
      const load =
        view === 'login'
          ? api.events(filter || undefined).then(setEvents)
          : api.adminEvents(filter || undefined).then(setAdminEvents);
      load.catch((e) => setError(e.message));
    }, 250);
    return () => clearTimeout(t);
  }, [filter, view]);

  return (
    <main>
      {error && <div className="error">{error}</div>}
      <div className="toolbar">
        <div className="segmented">
          <button className={view === 'login' ? 'active' : ''} onClick={() => setView('login')}>
            로그인 이력
          </button>
          <button className={view === 'admin' ? 'active' : ''} onClick={() => setView('admin')}>
            관리자 작업
          </button>
        </div>
        <input
          className="filter"
          placeholder={view === 'login' ? '이메일로 필터…' : '관리자·대상·작업으로 필터…'}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>
      {view === 'login' ? (
        <>
          <table>
            <thead>
              <tr>
                <th>시각</th>
                <th>이벤트</th>
                <th>이메일</th>
                <th>상세</th>
                <th>IP</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td className="nowrap" data-label="시각">{fmt(e.created_at)}</td>
                  <td data-label="이벤트">
                    <span className={`badge ${e.event}`}>{LABEL[e.event]}</span>
                  </td>
                  <td data-label="이메일">{e.email || '—'}</td>
                  <td className="muted small" data-label="상세">{e.detail ?? ''}</td>
                  <td className="muted small" data-label="IP">{e.ip ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {events.length === 0 && <p className="muted center">기록이 없습니다.</p>}
        </>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th>시각</th>
                <th>작업</th>
                <th>관리자</th>
                <th>대상</th>
                <th>상세</th>
                <th>IP</th>
              </tr>
            </thead>
            <tbody>
              {adminEvents.map((e) => (
                <tr key={e.id}>
                  <td className="nowrap" data-label="시각">{fmt(e.created_at)}</td>
                  <td data-label="작업">
                    <span className="badge logout">{ACTION[e.action] ?? e.action}</span>
                  </td>
                  <td data-label="관리자">{e.actor_email}</td>
                  <td data-label="대상">{e.target || '—'}</td>
                  <td className="muted small" data-label="상세">
                    {Object.keys(e.detail ?? {}).length ? JSON.stringify(e.detail) : ''}
                  </td>
                  <td className="muted small" data-label="IP">{e.ip ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {adminEvents.length === 0 && <p className="muted center">관리자 작업 기록이 없습니다.</p>}
        </>
      )}
    </main>
  );
}
