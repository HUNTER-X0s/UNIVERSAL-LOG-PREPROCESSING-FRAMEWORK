/**
 * Account Overrides Utility
 *
 * Keeps user profile modifications (display name, username, password, avatar)
 * synchronized with the User Authentication Page (LoginPage) and local session.
 */

export interface AccountOverride {
  originalUsername?: string;
  username?: string;
  displayName?: string;
  password?: string;
  avatarUrl?: string | null;
}

const STORAGE_KEY = 'ulpf_account_overrides';

export const CANONICAL_OPERATOR_ACCOUNTS = [
  { username: 'pradyumna.biswal', displayName: 'PRADYUMNA BISWAL', role: 'Analyst',            password: 'Ulpf@N4!yst#8x2K' },
  { username: 'rajesh.marshall',  displayName: 'RAJESH MARSHALL',  role: 'Viewer',             password: 'Ulpf@V!3wer#4mZ9' },
  { username: 'rashu.kaithwas',   displayName: 'RASHI KAITHWAS',   role: 'Operator',           password: 'Ulpf@0p3r#7nR1q' },
  { username: 'swadheenta.jeenu', displayName: 'SWADHEENTA SAMAL', role: 'Threat Hunter',      password: 'Ulpf@H4nt3r#9kLm' },
  { username: 'Subhankar.Swain',  displayName: 'Subhankar Swain',  role: 'Detection Engineer', password: 'Ulpf@D3tect#2pQw' },
  { username: 'simran.swain',     displayName: 'SIMRAN SWAIN',     role: 'Mapping Reviewer',   password: 'Ulpf@R3v!ew#6sYt' },
  { username: 'jahanabi.dalai',   displayName: 'JAHANABI DALAI',   role: 'Mapping Admin',      password: 'Ulpf@Adm!n#3fGh' },
  { username: 'anurag.swain',     displayName: 'ANURAG SWAIN',     role: 'Platform Admin',     password: 'Ulpf@Pl@tf#1rM!x' },
];

export function getAccountOverrides(): Record<string, AccountOverride> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

export function findAccountOverride(query: string): (AccountOverride & { key: string }) | undefined {
  if (!query) return undefined;
  const q = query.trim().toLowerCase();
  const overrides = getAccountOverrides();

  // 1. Direct key match or username match
  for (const [key, val] of Object.entries(overrides)) {
    if (
      key.toLowerCase() === q ||
      val.username?.toLowerCase() === q ||
      val.originalUsername?.toLowerCase() === q
    ) {
      return { ...val, key, originalUsername: val.originalUsername || key };
    }
  }

  // 2. Check canonical accounts
  const canonical = CANONICAL_OPERATOR_ACCOUNTS.find(
    (a) => a.username.toLowerCase() === q
  );
  if (canonical && overrides[canonical.username]) {
    const val = overrides[canonical.username];
    return { ...val, key: canonical.username, originalUsername: canonical.username };
  }

  return undefined;
}

export function saveAccountOverride(accountKey: string, updates: AccountOverride): void {
  try {
    const overrides = getAccountOverrides();
    // Locate if account was previously modified under another alias
    let targetKey = accountKey;
    for (const [key, val] of Object.entries(overrides)) {
      if (
        key.toLowerCase() === accountKey.toLowerCase() ||
        val.username?.toLowerCase() === accountKey.toLowerCase() ||
        val.originalUsername?.toLowerCase() === accountKey.toLowerCase()
      ) {
        targetKey = key;
        break;
      }
    }

    const existing = overrides[targetKey] || {};
    const originalUsername = existing.originalUsername || targetKey;

    overrides[targetKey] = {
      ...existing,
      ...updates,
      originalUsername,
    };

    // If new username was provided, also index under the new username
    if (updates.username && updates.username !== targetKey) {
      overrides[updates.username] = {
        ...overrides[targetKey],
        originalUsername,
      };
    }

    localStorage.setItem(STORAGE_KEY, JSON.stringify(overrides));
    // Dispatch a synthetic StorageEvent so same-tab listeners (e.g. LoginPage)
    // pick up the change without needing a cross-tab postMessage.
    try {
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: STORAGE_KEY,
          newValue: JSON.stringify(overrides),
          storageArea: localStorage,
        }),
      );
    } catch {
      /* SSR / test environments without window */
    }
  } catch {
    // Ignore storage quota/security errors
  }
}

export function applyAccountOverrides<
  T extends { username: string; displayName: string; password: string; avatarUrl?: string }
>(accounts: T[]): T[] {
  const overrides = getAccountOverrides();
  return accounts.map((acc) => {
    const match =
      overrides[acc.username] ||
      Object.values(overrides).find(
        (o) =>
          o.originalUsername?.toLowerCase() === acc.username.toLowerCase() ||
          o.username?.toLowerCase() === acc.username.toLowerCase()
      );
    if (!match) return acc;
    return {
      ...acc,
      username: match.username || acc.username,
      displayName: match.displayName || acc.displayName,
      password: match.password || acc.password,
      avatarUrl: match.avatarUrl !== undefined ? match.avatarUrl : acc.avatarUrl,
    };
  });
}
