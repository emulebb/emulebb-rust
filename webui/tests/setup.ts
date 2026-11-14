import "@testing-library/jest-dom/vitest";
import { act, cleanup } from "@testing-library/preact";
import { afterEach } from "vitest";

// WHY: Vitest globals are disabled, so Testing Library cannot register automatic cleanup.
// Drain the passive unmount effects scheduled by this cleanup before the DOM environment is disposed.
afterEach(() => act(cleanup));
