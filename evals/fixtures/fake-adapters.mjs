export function capability(overrides = {}) {
  return {
    id: 'native',
    version: 'test-1',
    state: 'ready',
    reason: 'fixture_ready',
    automatic: true,
    commands: ['url'],
    cost: 'local-zero',
    price: 0,
    networkModel: 'core-http',
    ...overrides,
  };
}

export function scriptedAdapter(outcomes) {
  const script = [...outcomes];
  const calls = [];
  return {
    calls,
    async run(job) {
      calls.push(job);
      if (script.length === 0) throw new Error('script exhausted');
      const next = script.shift();
      if (next instanceof Error) throw next;
      return typeof next === 'function' ? next(job, calls.length) : next;
    },
  };
}
