import { useCallback, useEffect, useMemo, useState } from 'react';

type UseApiOptions<T> = {
  fallbackData?: T;
  fallbackWarning?: string;
};

export function useApi<T>(fetcher: () => Promise<T>, deps: unknown[] = [], options: UseApiOptions<T> = {}) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);

  const run = useCallback(async () => {
    setLoading(true);
    setError(null);
    setWarning(null);
    try {
      const result = await fetcher();
      setData(result);
    } catch (err: any) {
      if (options.fallbackData !== undefined) {
        setData(options.fallbackData);
        setWarning(options.fallbackWarning || 'Backend unavailable. Showing demo data.');
      } else {
        setError(err?.message || 'Request failed');
      }
    } finally {
      setLoading(false);
    }
  }, deps);

  useEffect(() => {
    void run();
  }, [run]);

  return useMemo(() => ({ data, loading, error, warning, retry: run, setData }), [data, loading, error, warning, run]);
}
