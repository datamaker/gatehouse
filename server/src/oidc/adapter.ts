import { query } from '../db/pool.js';

/**
 * oidc-provider storage adapter.
 *
 * - `Client` reads live from Postgres so clients added in the console work
 *   without a restart.
 * - Everything else (codes, tokens, sessions, interactions) is in-memory:
 *   a restart just sends users through the silent gatehouse re-auth redirect.
 */

interface StoredPayload {
  payload: Record<string, unknown>;
  expiresAt: number | null;
}

const stores = new Map<string, Map<string, StoredPayload>>();
const grantIndex = new Map<string, Set<{ name: string; id: string }>>();
const userCodeIndex = new Map<string, string>();
const uidIndex = new Map<string, string>();

function store(name: string): Map<string, StoredPayload> {
  let s = stores.get(name);
  if (!s) {
    s = new Map();
    stores.set(name, s);
  }
  return s;
}

export class GatehouseAdapter {
  constructor(private name: string) {}

  async upsert(id: string, payload: Record<string, unknown>, expiresIn?: number): Promise<void> {
    store(this.name).set(id, {
      payload,
      expiresAt: expiresIn ? Date.now() + expiresIn * 1000 : null,
    });
    const grantId = payload.grantId as string | undefined;
    if (grantId) {
      let set = grantIndex.get(grantId);
      if (!set) {
        set = new Set();
        grantIndex.set(grantId, set);
      }
      set.add({ name: this.name, id });
    }
    if (payload.userCode) userCodeIndex.set(payload.userCode as string, id);
    if (payload.uid) uidIndex.set(payload.uid as string, id);
  }

  async find(id: string): Promise<Record<string, unknown> | undefined> {
    if (this.name === 'Client') return findClient(id);
    const entry = store(this.name).get(id);
    if (!entry) return undefined;
    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      store(this.name).delete(id);
      return undefined;
    }
    return entry.payload;
  }

  async findByUserCode(userCode: string): Promise<Record<string, unknown> | undefined> {
    const id = userCodeIndex.get(userCode);
    return id ? this.find(id) : undefined;
  }

  async findByUid(uid: string): Promise<Record<string, unknown> | undefined> {
    const id = uidIndex.get(uid);
    return id ? this.find(id) : undefined;
  }

  async consume(id: string): Promise<void> {
    const entry = store(this.name).get(id);
    if (entry) entry.payload.consumed = Math.floor(Date.now() / 1000);
  }

  async destroy(id: string): Promise<void> {
    store(this.name).delete(id);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    const set = grantIndex.get(grantId);
    if (!set) return;
    for (const { name, id } of set) store(name).delete(id);
    grantIndex.delete(grantId);
  }
}

/**
 * 한 계정의 OP 상태를 전부 지운다: Session·Grant 와 그 계정으로 발급된 코드·토큰·진행 중 interaction.
 * 로그아웃·관리자 세션 종료·비활성화 때 부른다 — sessions 테이블만 지우면 브라우저의 OP 세션이 남아
 * authorization code 가 계속 나간다. 저장소가 메모리라 이 프로세스 안에서 바로 끝난다.
 * 지운 항목 수를 돌려준다.
 */
export function revokeAccount(accountId: string): number {
  let removed = 0;
  for (const [name, s] of stores) {
    if (name === 'Client') continue;
    for (const [id, entry] of s) {
      const p = entry.payload as {
        accountId?: string;
        session?: { accountId?: string };
        result?: { login?: { accountId?: string } };
      };
      const owner = p.accountId ?? p.session?.accountId ?? p.result?.login?.accountId;
      if (owner !== accountId) continue;
      s.delete(id);
      if (name === 'Grant') grantIndex.delete(id);
      removed++;
    }
  }
  return removed;
}

async function findClient(clientId: string): Promise<Record<string, unknown> | undefined> {
  const { rows } = await query<{
    client_id: string;
    client_secret: string;
    name: string;
    redirect_uris: string[];
    grant_types: string[];
    token_endpoint_auth_method: string;
  }>(
    `SELECT client_id, client_secret, name, redirect_uris, grant_types, token_endpoint_auth_method
     FROM oidc_clients WHERE client_id = $1`,
    [clientId],
  );
  const c = rows[0];
  if (!c) return undefined;
  const usesCode = c.grant_types.includes('authorization_code');
  return {
    client_id: c.client_id,
    client_name: c.name,
    grant_types: c.grant_types,
    response_types: usesCode ? ['code'] : [],
    token_endpoint_auth_method: c.token_endpoint_auth_method,
    ...(c.token_endpoint_auth_method === 'none' ? {} : { client_secret: c.client_secret }),
    ...(c.redirect_uris.length > 0 ? { redirect_uris: c.redirect_uris } : {}),
  };
}
