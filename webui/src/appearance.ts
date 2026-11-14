export type AppearancePreference = "system" | "light" | "dark";

export const APPEARANCE_STORAGE_KEY = "emulebb.webui.theme";

export function appearancePreference(value: unknown): AppearancePreference {
  return value === "light" || value === "dark" ? value : "system";
}

/** Browser-only appearance state, independent of daemon settings and credentials. */
export function createAppearance(
  root: HTMLElement,
  storage: () => Storage,
  media: MediaQueryList
) {
  let preference: AppearancePreference = "system";
  try {
    preference = appearancePreference(storage().getItem(APPEARANCE_STORAGE_KEY));
  } catch {
    // Storage can be unavailable in private or restricted browser contexts.
  }
  const subscribers = new Set<(value: AppearancePreference) => void>();
  const apply = () => {
    const resolved = preference === "system" ? media.matches ? "dark" : "light" : preference;
    root.dataset.bsTheme = resolved;
    root.style.colorScheme = resolved;
  };
  const onDeviceChange = () => {
    if (preference === "system") apply();
  };
  // Apply before the initial application render, including the locked screen.
  apply();
  return {
    getPreference: () => preference,
    setPreference(value: AppearancePreference) {
      preference = appearancePreference(value);
      try {
        storage().setItem(APPEARANCE_STORAGE_KEY, preference);
      } catch {
        // Keep the selected appearance in memory for this page session.
      }
      apply();
      subscribers.forEach((subscriber) => subscriber(preference));
    },
    subscribe(subscriber: (value: AppearancePreference) => void) {
      if (subscribers.size === 0) media.addEventListener("change", onDeviceChange);
      subscribers.add(subscriber);
      apply();
      return () => {
        subscribers.delete(subscriber);
        if (subscribers.size === 0) media.removeEventListener("change", onDeviceChange);
      };
    }
  };
}

export type Appearance = ReturnType<typeof createAppearance>;
