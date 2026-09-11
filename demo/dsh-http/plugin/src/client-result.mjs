export function unwrapDemoResult(result) {
  if (!result?.ok) throw new Error(result?.error?.message ?? 'Demo service unavailable');
  const value = result.value;
  if (!value || typeof value.phase !== 'string' || !Array.isArray(value.events)) {
    throw new Error('Invalid demo service response');
  }
  return value;
}
