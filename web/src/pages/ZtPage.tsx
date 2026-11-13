import { useEffect, useState } from 'react';
import { api, type ZtCheck, type ZtConfig } from '../api';

const VERDICT: Record<string, string> = {
  compliant: '준수',
  noncompliant: '미준수',
  unknown: '미확인',
  no_device: '기기 없음',
  error: 'ward 오류',
  exempt: '면제',
};

// ward 가 verdict 에 덧붙이는 기계용 사유. 모르는 값은 그대로 보여 준다.
const REASON: Record<string, string> = { agent_offline: '에이전트 오프라인(최근 3분 미보고)' };

const MODE: Record<string, string> = { off: '꺼짐', monitor: '기록만', enforce: '차단' };

export function ZtPage() {
  const [cfg, setCfg] = useState<ZtConfig | null>(null);
  const [checks, setChecks] = useState<ZtCheck[]>([]);
  const [filter, setFilter] = useState('');
  const [deniedOnly, setDeniedOnly] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    api.ztConfig().then(setCfg).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    const t = setTimeout(() => {
      api
        .ztChecks(filter || undefined, deniedOnly)
        .then(setChecks)
        .catch((e) => setError(e.message));
    }, 250);
    return () => clearTimeout(t);
  }, [filter, deniedOnly]);

  return (
    <main>
      {error && <div className="error">{error}</div>}
      {cfg && (
        <div className="card zt-config">
          <div>
            <b>모드</b> <span className={`badge zt-${cfg.mode}`}>{MODE[cfg.mode] ?? cfg.mode}</span>
            {cfg.mode !== 'off' && !cfg.secret_set && (
              <span className="muted small"> · 시크릿 미설정 — ward 조회가 전부 실패합니다</span>
            )}
          </div>
          <div className="muted small">
            ward {cfg.ward_url} · ward 장애 시 {cfg.fail_open ? '통과(fail-open)' : '차단(fail-closed)'} · 캐시 {cfg.cache_sec}초 · 타임아웃{' '}
            {cfg.timeout_ms}ms
          </div>
          <div className="muted small">
            면제 이메일: {cfg.exempt_emails.length ? cfg.exempt_emails.join(', ') : '없음'} · 면제 호스트:{' '}
            {cfg.exempt_hosts.length ? cfg.exempt_hosts.join(', ') : '없음'} · 제한 접근 호스트:{' '}
            {cfg.soft_hosts.length ? cfg.soft_hosts.join(', ') : '없음'}
            {cfg.soft_hosts.length > 0 && ' (차단 대신 통과시키고 앱이 권한을 줄입니다)'}
          </div>
          <div className="small">
            <b>사용자별 차단(enforce)</b>{' '}
            {cfg.enforce_count > 0 ? (
              <>
                <span className="badge zt-enforce">{cfg.enforce_count}명</span>{' '}
                <span className="muted">{cfg.enforce_emails.join(', ')}</span>
                {cfg.mode === 'off' && <span className="muted"> · 전역 모드가 꺼져 있어 적용되지 않습니다</span>}
                {cfg.mode === 'enforce' && <span className="muted"> · 전역 모드가 차단이라 전원에게 적용됩니다</span>}
              </>
            ) : (
              <span className="muted">없음</span>
            )}
          </div>
          <div className="muted small">
            OIDC 로그인: 차단 대상 사용자는 웹 클라이언트 로그인도 막습니다. device grant 클라이언트(CLI·VPN)는 기록만
            {cfg.oidc_exempt_clients.length > 0 && <> · 추가 제외: {cfg.oidc_exempt_clients.join(', ')}</>}
          </div>
          <div className="muted small">설정은 환경 변수(GATEHOUSE_ZT_*)로 바꿉니다. 여기서는 읽기만 됩니다.</div>
        </div>
      )}
      <div className="toolbar">
        <input
          className="filter"
          placeholder="이메일로 필터…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <label className="small">
          <input type="checkbox" checked={deniedOnly} onChange={(e) => setDeniedOnly(e.target.checked)} /> 거부만
        </label>
      </div>
      <table>
        <thead>
          <tr>
            <th>시각</th>
            <th>판정</th>
            <th>이메일</th>
            <th>앱(호스트)</th>
            <th>기기</th>
            <th>IP</th>
            <th>모드</th>
          </tr>
        </thead>
        <tbody>
          {checks.map((c) => (
            <tr key={c.id} className={c.allowed ? (c.restricted ? 'restricted-row' : '') : 'denied-row'}>
              <td className="nowrap" data-label="시각">
                {new Date(c.created_at).toLocaleString('ko-KR', { dateStyle: 'short', timeStyle: 'medium' })}
              </td>
              <td data-label="판정">
                <span className={`badge zt-${c.verdict} ${c.allowed ? '' : 'denied'}`}>
                  {VERDICT[c.verdict] ?? c.verdict}
                  {!c.allowed && ' · 차단됨'}
                </span>
                {c.restricted && <span className="badge zt-restricted">제한 접근</span>}
                {c.reason && <div className="muted small">{REASON[c.reason] ?? c.reason}</div>}
                {c.error && <div className="muted small">{c.error}</div>}
              </td>
              <td data-label="이메일">{c.email}</td>
              <td className="muted small" data-label="앱">{c.host}</td>
              <td className="muted small" data-label="기기">
                {c.device_hostname ?? (c.device_id ? c.device_id.slice(0, 8) : '—')}
              </td>
              <td className="muted small" data-label="IP">{c.ip}</td>
              <td className="muted small" data-label="모드">{MODE[c.mode] ?? c.mode}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {checks.length === 0 && <p className="muted center">판정 기록이 없습니다. 모드가 꺼져 있으면 아무것도 기록되지 않습니다.</p>}
    </main>
  );
}
