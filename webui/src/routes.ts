export type Tab =
  | "overview"
  | "downloads"
  | "search"
  | "sharing"
  | "library"
  | "uploads"
  | "network"
  | "servers"
  | "kad"
  | "categories"
  | "friends"
  | "settings"
  | "diagnostics"
  | "logs";

export type AppRoute = {
  tab: Tab;
  searchId?: string;
  mobile?: true;
};

const TAB_PATHS: Record<Tab, string> = {
  overview: "/",
  downloads: "/downloads",
  search: "/searches",
  sharing: "/sharing",
  "library": "/library",
  uploads: "/uploads",
  network: "/network",
  servers: "/servers",
  kad: "/kad",
  categories: "/categories",
  friends: "/friends",
  settings: "/settings",
  diagnostics: "/diagnostics",
  logs: "/logs"
};

const PATH_TABS = new Map(Object.entries(TAB_PATHS).map(([tab, path]) => [path, tab as Tab]));

export function routeFromPathname(pathname: string): AppRoute | null {
  const normalized = normalizePathname(pathname);
  if (normalized === "/mobile") return { tab: "downloads", mobile: true };
  if (normalized === "/mobile/more") return { tab: "overview", mobile: true };
  if (normalized === "/mobile/searches") return { tab: "search", mobile: true };
  const mobileSearch = /^\/mobile\/searches\/([1-9]\d*)$/.exec(normalized);
  if (mobileSearch && isSearchId(mobileSearch[1])) {
    return { tab: "search", searchId: mobileSearch[1], mobile: true };
  }
  const tab = PATH_TABS.get(normalized);
  if (tab) {
    return { tab };
  }

  const searchMatch = /^\/searches\/([1-9]\d*)$/.exec(normalized);
  if (!searchMatch || !isSearchId(searchMatch[1])) {
    return null;
  }
  return { tab: "search", searchId: searchMatch[1] };
}

export function pathForTab(tab: Tab): string {
  return TAB_PATHS[tab];
}

export function pathForSearch(searchId: string): string {
  if (!isSearchId(searchId)) {
    throw new Error(`Invalid search session id: ${searchId}`);
  }
  return `/searches/${searchId}`;
}

export function pathForRoute(route: AppRoute): string {
  if (route.mobile) {
    if (route.tab === "downloads") return "/mobile";
    if (route.tab === "overview") return "/mobile/more";
    if (route.tab === "search") return `/mobile${route.searchId ? pathForSearch(route.searchId) : pathForTab("search")}`;
  }
  return route.tab === "search" && route.searchId
    ? pathForSearch(route.searchId)
    : pathForTab(route.tab);
}

/** Choose a phone view only for destinations the phone interface implements. */
export function defaultMobileRoute(route: AppRoute): AppRoute {
  if (route.mobile) return route;
  if (route.tab === "overview") return { tab: "downloads", mobile: true };
  if (route.tab === "downloads" || route.tab === "search") return { ...route, mobile: true };
  return route;
}

function normalizePathname(pathname: string): string {
  if (!pathname.startsWith("/")) {
    return "/";
  }
  return pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
}

function isSearchId(value: string): boolean {
  if (!/^[1-9]\d*$/.test(value)) {
    return false;
  }
  const numeric = Number(value);
  return Number.isSafeInteger(numeric) && numeric <= 0xffff_ffff;
}
