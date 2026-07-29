// Manual light/dark override, shared with the explorer's model: a `data-theme` attribute on
// <html> wins over the OS `prefers-color-scheme` in both directions (see styles.css). "system"
// removes the attribute and lets the OS preference through. Persisted so the choice survives
// restarts; applied once at startup (main.tsx) before first paint to avoid a theme flash.
export type ThemePref = "system" | "light" | "dark";

const KEY = "helix-theme";

export function getThemePref(): ThemePref {
  const v = localStorage.getItem(KEY);
  return v === "light" || v === "dark" ? v : "system";
}

export function applyStoredTheme(): void {
  const pref = getThemePref();
  const root = document.documentElement;
  if (pref === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", pref);
}

export function setThemePref(pref: ThemePref): void {
  if (pref === "system") localStorage.removeItem(KEY);
  else localStorage.setItem(KEY, pref);
  applyStoredTheme();
}
