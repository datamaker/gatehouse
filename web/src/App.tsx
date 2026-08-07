import { useEffect, useState } from 'react';
import { api, type Me } from './api';
import { UsersPage } from './pages/UsersPage';
import { AuditPage } from './pages/AuditPage';
import { ClientsPage } from './pages/ClientsPage';

type Tab = 'users' | 'clients' | 'audit';

export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [tab, setTab] = useState<Tab>('users');

  useEffect(() => {
    api.me().then(setMe).catch(() => {});
  }, []);

  if (!me) return <div className="center muted">loading…</div>;

  return (
    <div className="shell">
      <header>
        <div className="brand">
          <span className="brand-mark">⌂</span> gatehouse
        </div>
        <div className="who">
          {me.picture && <img src={me.picture} alt="" referrerPolicy="no-referrer" />}
          <span>{me.name || me.email}</span>
          <form method="post" action="/logout">
            <button className="ghost">로그아웃</button>
          </form>
        </div>
      </header>

      {me.is_admin ? (
        <>
          <nav>
            <button className={tab === 'users' ? 'active' : ''} onClick={() => setTab('users')}>
              사용자
            </button>
            <button className={tab === 'clients' ? 'active' : ''} onClick={() => setTab('clients')}>
              OIDC 클라이언트
            </button>
            <button className={tab === 'audit' ? 'active' : ''} onClick={() => setTab('audit')}>
              감사 로그
            </button>
          </nav>
          {tab === 'users' && <UsersPage me={me} />}
          {tab === 'clients' && <ClientsPage />}
          {tab === 'audit' && <AuditPage />}
        </>
      ) : (
        <div className="center">
          <div className="card profile">
            {me.picture && <img src={me.picture} alt="" referrerPolicy="no-referrer" />}
            <h2>{me.name || me.email}</h2>
            <p className="muted">{me.email}</p>
            <p className="muted small">로그인되어 있습니다. 이 세션으로 사내 서비스에 접근할 수 있습니다.</p>
          </div>
        </div>
      )}
    </div>
  );
}
