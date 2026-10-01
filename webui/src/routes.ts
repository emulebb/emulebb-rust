export type Tab =
  | "overview"
  | "transfers"
  | "search"
  | "sharing"
  | "shared-files"
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
};

const TAB_PATHS: Record<Tab, string> = {
  overview: "/",
  transfers: "/transfers",
  search: "/searches",
  sharing: "/sharing",
  "shared-files": "/shared-files",
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
  return route.tab === "search" && route.searchId
    ? pathForSearch(route.searchId)
    : pathForTab(route.tab);
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
