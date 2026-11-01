import type { StorageManager } from "@mui/system";

/** Only this non-sensitive preference is shared. Authentication stays host-only. */
export const MODE_STORAGE_KEY = "i3alumba-color-mode";
export const THEME_COOKIE = "i3alumba-theme";
type Mode = "light" | "dark" | "system";
const validMode = (value: unknown): value is Mode =>
  value === "light" || value === "dark" || value === "system";
const memory = new Map<string, string>();

export function createThemeStorageManager(legacyKey?: string): StorageManager {
  return ({ key, storageWindow }) => {
    const win =
      storageWindow ?? (typeof window === "undefined" ? undefined : window);
    const shared = key === MODE_STORAGE_KEY;
    const cookie = (): Mode | undefined => {
      try {
        const raw = win?.document.cookie
          .split(";")
          .map((item) => item.trim())
          .find((item) => item.startsWith(`${THEME_COOKIE}=`))
          ?.slice(THEME_COOKIE.length + 1);
        return validMode(raw) ? raw : undefined;
      } catch {
        return undefined;
      }
    };
    const local = (name: string): string | undefined => {
      try {
        return win?.localStorage.getItem(name) ?? undefined;
      } catch {
        return undefined;
      }
    };
    const read = (): string | undefined => {
      if (shared) {
        const preference = cookie();
        if (preference) return preference;
      }
      const value = local(key) ?? memory.get(key);
      return shared ? (validMode(value) ? value : undefined) : value;
    };
    const save = (value: string) => {
      memory.set(key, value);
      try {
        win?.localStorage.setItem(key, value);
      } catch {
        /* In-memory fallback. */
      }
      if (!shared || !win) return;
      try {
        const hostname = win.location.hostname;
        const domain =
          hostname === "i3alumba.ru" || hostname.endsWith(".i3alumba.ru")
            ? "; Domain=i3alumba.ru"
            : "";
        const secure = win.location.protocol === "https:" ? "; Secure" : "";
        win.document.cookie = `${THEME_COOKIE}=${value}; Path=/; Max-Age=31536000; SameSite=Lax${domain}${secure}`;
      } catch {
        /* Cookie denial must not break the page. */
      }
    };
    return {
      get(defaultValue: unknown) {
        const current = read();
        if (current !== undefined) return current;
        const legacy = shared && legacyKey ? local(legacyKey) : undefined;
        if (validMode(legacy)) {
          save(legacy);
          return legacy;
        }
        return defaultValue;
      },
      set(value: unknown) {
        if (typeof value !== "string" || (shared && !validMode(value))) return;
        save(value);
        win?.dispatchEvent(new Event("i3alumba-theme-change"));
      },
      subscribe(handler: (value: string) => void) {
        if (!win) return () => {};
        let previous = read();
        const check = () => {
          const next = read();
          if (next !== undefined && next !== previous) {
            previous = next;
            handler(next);
          }
        };
        const storage = (event: StorageEvent) => {
          if (event.key !== key) return;
          // A same-origin writer may still use the legacy localStorage mechanism.
          if (shared && validMode(event.newValue)) save(event.newValue);
          check();
        };
        win.addEventListener("storage", storage);
        win.addEventListener("focus", check);
        win.addEventListener("pageshow", check);
        win.addEventListener("i3alumba-theme-change", check);
        win.document.addEventListener("visibilitychange", check);
        // Cookies have no universally supported cross-origin change event.
        const timer = shared ? win.setInterval(check, 1000) : undefined;
        return () => {
          win.removeEventListener("storage", storage);
          win.removeEventListener("focus", check);
          win.removeEventListener("pageshow", check);
          win.removeEventListener("i3alumba-theme-change", check);
          win.document.removeEventListener("visibilitychange", check);
          if (timer !== undefined) win.clearInterval(timer);
        };
      },
    };
  };
}
