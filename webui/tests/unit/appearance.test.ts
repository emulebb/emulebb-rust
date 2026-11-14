import { afterEach, describe, expect, it, vi } from "vitest";

import { APPEARANCE_STORAGE_KEY, createAppearance } from "../../src/appearance";

function device(dark: boolean) {
  const media = Object.assign(new EventTarget(), { matches: dark }) as unknown as MediaQueryList;
  return {
    media,
    change(value: boolean) {
      Object.defineProperty(media, "matches", { configurable: true, value });
      media.dispatchEvent(new Event("change"));
    }
  };
}

afterEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-bs-theme");
  document.documentElement.style.colorScheme = "";
});

describe("appearance", () => {
  it.each([null, "", "invalid", "system"])("defaults %s to System before rendering and follows device changes", (saved) => {
    if (saved !== null) localStorage.setItem(APPEARANCE_STORAGE_KEY, saved);
    const system = device(true);
    const appearance = createAppearance(document.documentElement, () => localStorage, system.media);
    expect(appearance.getPreference()).toBe("system");
    expect(document.documentElement.dataset.bsTheme).toBe("dark");
    const unsubscribe = appearance.subscribe(() => {});
    system.change(false);
    expect(document.documentElement.dataset.bsTheme).toBe("light");
    expect(document.documentElement.style.colorScheme).toBe("light");
    unsubscribe();
  });

  it("persists explicit choices independently from authentication and overrides device changes", () => {
    localStorage.setItem("emulebb.webui.apiKey", "synthetic-key");
    const system = device(true);
    const appearance = createAppearance(document.documentElement, () => localStorage, system.media);
    const subscriber = vi.fn();
    const unsubscribe = appearance.subscribe(subscriber);
    appearance.setPreference("light");
    system.change(true);
    expect(document.documentElement.dataset.bsTheme).toBe("light");
    expect(localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBe("light");
    expect(localStorage.getItem("emulebb.webui.apiKey")).toBe("synthetic-key");
    expect(subscriber).toHaveBeenCalledWith("light");
    const reload = createAppearance(document.documentElement, () => localStorage, system.media);
    expect(reload.getPreference()).toBe("light");
    appearance.setPreference("system");
    expect(document.documentElement.dataset.bsTheme).toBe("dark");
    unsubscribe();
  });

  it("keeps a working session preference when storage is denied and removes the media listener", () => {
    const system = device(false);
    const remove = vi.spyOn(system.media, "removeEventListener");
    const appearance = createAppearance(document.documentElement, () => { throw new Error("Storage denied"); }, system.media);
    const unsubscribe = appearance.subscribe(() => {});
    appearance.setPreference("dark");
    expect(appearance.getPreference()).toBe("dark");
    expect(document.documentElement.dataset.bsTheme).toBe("dark");
    unsubscribe();
    expect(remove).toHaveBeenCalledOnce();
    appearance.setPreference("system");
    system.change(true);
    expect(document.documentElement.dataset.bsTheme).toBe("light");
  });
});
