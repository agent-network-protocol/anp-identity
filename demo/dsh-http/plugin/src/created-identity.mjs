// Use the confirmed request snapshot, never infer a Handle from the DID or name.
export function confirmedHandle(request) {
  if (request.kind !== 'create' || request.status !== 'approved' || request.executionStatus !== 'succeeded' || !request.result?.reference) {
    throw new Error('creation_result_unavailable');
  }
  return request.parameters?.handle ?? null;
}
