import { useLayoutEffect, useRef } from "preact/hooks";

/** Keep one read in flight for the current query and coalesce updates during it. */
export function useRefreshRead(read: ((signal: AbortSignal) => Promise<void>) | null, generation: number) {
  const request = useRef<(() => void) | null>(null);

  useLayoutEffect(() => {
    if (!read) return;
    const controller = new AbortController();
    let busy = false;
    let pending = false;
    request.current = () => {
      if (busy) {
        pending = true;
        return;
      }
      busy = true;
      void read(controller.signal).finally(() => {
        busy = false;
        if (pending && !controller.signal.aborted) {
          pending = false;
          request.current?.();
        }
      });
    };
    return () => {
      request.current = null;
      controller.abort();
    };
  }, [read]);

  useLayoutEffect(() => {
    request.current?.();
  }, [read, generation]);
}
