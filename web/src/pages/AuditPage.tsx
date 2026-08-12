import { useEffect, useState } from 'react';
import { api, type LoginEvent } from '../api';

const LABEL: Record<LoginEvent['event'], string> = {
  login: '로그인',
  logout: '로그아웃',
  denied: '거부',
};

export function AuditPage() {
  const [events, setEvents] = useState<LoginEvent[]>([]);
  const [filter, setFilter] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    const t = setTimeout(() => {
      api
        .events(filter || undefined)
        .then(setEvents)
        .catch((e) => setError(e.message));
    }, 250);
    return () => clearTimeout(t);
  }, [filter]);

  return (
    <main>
      {error && <div className="error">{error}</div>}
      <input
        className="filter"
        placeholder="이메일로 필터…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
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
              <td className="nowrap" data-label="시각">
                {new Date(e.created_at).toLocaleString('ko-KR', {
                  dateStyle: 'short',
                  timeStyle: 'medium',
                })}
              </td>
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
    </main>
  );
}
