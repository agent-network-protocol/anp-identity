import { z } from 'zod';
export default {
  package: 'anp-http-demo',
  descriptors: ['status', 'start', 'send', 'checks'].map(method => ({
    id: `anp-http-demo#anpHttpDemo/${method}`, service: 'anpHttpDemo', namespace: 'anpHttpDemo', method,
    invocation: { kind: 'direct' }, parameters: [],
    result: { mode: 'strict', typeSymbol: `anp-http-demo#${method}Result`, schema: z.json() },
  })),
};
