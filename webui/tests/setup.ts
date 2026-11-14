import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/preact";
import { afterEach } from "vitest";

// WHY: Vitest globals are disabled, so Testing Library cannot register automatic cleanup.
afterEach(cleanup);
