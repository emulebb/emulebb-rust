import { render } from "preact";

import { App } from "./app";
import { createAppearance } from "./appearance";

const appearance = createAppearance(
  document.documentElement,
  () => window.localStorage,
  window.matchMedia("(prefers-color-scheme: dark)")
);
render(<App appearance={appearance} />, document.getElementById("app")!);
