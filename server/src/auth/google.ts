import * as oidc from 'openid-client';
import { config, baseUrl } from '../config.js';

let google: oidc.Configuration;

export async function initGoogle(): Promise<void> {
  google = await oidc.discovery(
    new URL('https://accounts.google.com'),
    config.googleClientId,
    config.googleClientSecret,
  );
}

export interface AuthStart {
  url: string;
  state: string;
  codeVerifier: string;
}

export async function buildAuthUrl(): Promise<AuthStart> {
  const codeVerifier = oidc.randomPKCECodeVerifier();
  const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
  const state = oidc.randomState();

  const url = oidc.buildAuthorizationUrl(google, {
    redirect_uri: `${baseUrl()}/callback`,
    scope: 'openid email profile',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
    // `hd` only pre-filters Google's account chooser; the claim is verified
    // server-side in the callback regardless.
    hd: config.allowedDomains.length === 1 ? config.allowedDomains[0] : '*',
    prompt: 'select_account',
  });

  return { url: url.href, state, codeVerifier };
}

export interface GoogleIdentity {
  sub: string;
  email: string;
  hd: string;
  name: string;
  picture: string | null;
}

/**
 * Exchanges the callback code and enforces the Workspace-domain policy.
 * Throws with a human-readable message on any policy violation.
 */
export async function handleCallback(
  currentUrl: URL,
  state: string,
  codeVerifier: string,
): Promise<GoogleIdentity> {
  const tokens = await oidc.authorizationCodeGrant(google, currentUrl, {
    pkceCodeVerifier: codeVerifier,
    expectedState: state,
  });

  const claims = tokens.claims();
  if (!claims) throw new Error('no ID token in Google response');

  const email = String(claims.email ?? '');
  // Personal Gmail accounts have no `hd` claim and are rejected here.
  const hd = String(claims.hd ?? '').toLowerCase();

  if (claims.email_verified !== true) {
    throw new Error(`email not verified: ${email}`);
  }
  if (!hd || !config.allowedDomains.includes(hd)) {
    throw new Error(`domain not allowed: ${email} (hd=${hd || 'none'})`);
  }

  return {
    sub: claims.sub,
    email,
    hd,
    name: String(claims.name ?? ''),
    picture: claims.picture ? String(claims.picture) : null,
  };
}
