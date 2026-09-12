import { KEY_PROFILES } from "../config/keyProfiles";
import { allowedIdentities, identityNamespace, loadConfig } from "../gateway/config";
import type { AuthResult, Env } from "../types";

function timingSafeEqualStr(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  if (aBytes.byteLength !== bBytes.byteLength) {
    crypto.subtle.timingSafeEqual(aBytes, aBytes);
    return false;
  }
  return crypto.subtle.timingSafeEqual(aBytes, bBytes);
}

function getBearerToken(request: Request): string | null {
  const auth = request.headers.get("authorization");
  if (auth?.toLowerCase().startsWith("bearer ")) {
    return auth.slice("bearer ".length).trim();
  }
  return request.headers.get("x-api-key");
}


async function bindRequestedIdentityNamespace(
  request: Request,
  env: Env,
  auth: AuthResult
): Promise<AuthResult> {
  if (auth.profile.debug) return auth;
  const requested = new URL(request.url).searchParams.get("namespace")?.trim();
  if (!requested || requested === auth.profile.namespace) return auth;

  try {
    const config = await loadConfig(env);
    const allowed = allowedIdentities(config, auth).some(
      (identity) => identityNamespace(identity) === requested
    );
    if (!allowed) return auth;
    return { ...auth, profile: { ...auth.profile, namespace: requested } };
  } catch {
    return auth;
  }
}

async function authenticated(
  request: Request,
  env: Env,
  profile: AuthResult["profile"],
  keyName: AuthResult["keyName"]
): Promise<AuthResult> {
  return bindRequestedIdentityNamespace(request, env, { ok: true, profile, keyName });
}

export async function authenticate(request: Request, env: Env): Promise<AuthResult | { ok: false }> {
  const token = getBearerToken(request);
  if (!token) return { ok: false };

  if (env.CHATBOX_API_KEY && timingSafeEqualStr(token, env.CHATBOX_API_KEY)) {
    return authenticated(request, env, KEY_PROFILES.chatbox, "CHATBOX_API_KEY");
  }

  if (env.IM_API_KEY && timingSafeEqualStr(token, env.IM_API_KEY)) {
    return authenticated(request, env, KEY_PROFILES.im, "IM_API_KEY");
  }

  if (env.DEBUG_API_KEY && timingSafeEqualStr(token, env.DEBUG_API_KEY)) {
    return authenticated(request, env, KEY_PROFILES.debug, "DEBUG_API_KEY");
  }

  if (env.MEMORY_MCP_API_KEY && timingSafeEqualStr(token, env.MEMORY_MCP_API_KEY)) {
    return authenticated(request, env, KEY_PROFILES.mcp, "MEMORY_MCP_API_KEY");
  }

  if (env.GUIDE_DOG_API_KEY && timingSafeEqualStr(token, env.GUIDE_DOG_API_KEY)) {
    return authenticated(request, env, KEY_PROFILES.guideDog, "GUIDE_DOG_API_KEY");
  }

  return { ok: false };
}
