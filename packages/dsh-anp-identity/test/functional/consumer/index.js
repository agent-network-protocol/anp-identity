import { writeFile } from 'node:fs/promises'

export const name = 'anp-identity-functional-e2e-consumer'
export const inject = ['anpIdentity']

const CONSUMER = 'anp-http-functional-e2e'

export function apply(ctx, config) {
  const exit = ctx.get('appExit')
  if (exit === undefined) {
    throw new Error('anp-identity-functional-e2e: DSH must provide ctx.appExit')
  }
  run(ctx, config).then((result) => {
    process.stdout.write(`ANP_HTTP_FUNCTIONAL_E2E ${JSON.stringify(result)}\n`)
    exit(0)
  }).catch((error) => {
    const message = error instanceof Error ? error.message : String(error)
    process.stderr.write(`anp-identity-functional-e2e: ${message}\n`)
    exit(1)
  })
}

async function run(ctx, config) {
  const verifierOrigin = requiredString(config?.verifierOrigin, 'verifierOrigin')
  const didDocumentPath = requiredString(config?.didDocumentPath, 'didDocumentPath')
  const resultPath = requiredString(config?.resultPath, 'resultPath')
  const parsedOrigin = new URL(verifierOrigin)
  if (parsedOrigin.protocol !== 'https:' || parsedOrigin.origin !== verifierOrigin) {
    throw new Error('verifierOrigin must be an exact HTTPS origin')
  }

  await waitForProvider(ctx)
  const lease = await ctx.anpIdentity.acquireClient({
    consumer: CONSUMER,
    capabilities: ['identity:read', 'identity:create', 'identity:http-auth'],
    httpOrigins: [verifierOrigin],
  })
  try {
    const identity = await lease.create({
      requestId: 'functional-e2e-create',
      identity: {
        profile: 'e1',
        domain: parsedOrigin.hostname,
        port: Number(parsedOrigin.port),
        pathSegments: ['dsh', 'http-functional-e2e'],
        capabilities: { didWba: true },
        managedKeys: [
          { fragment: 'root', role: 'root_control' },
          { fragment: 'request', role: 'request_signing' },
        ],
      },
    })
    const publicIdentity = await identity.publicIdentity()
    await writeFile(didDocumentPath, `${JSON.stringify(publicIdentity.document)}\n`, { mode: 0o600 })

    const getResponse = await identity.authenticatedHttp.dispatch(
      new Request(`${verifierOrigin}/functional/get`),
      request => fetch(request),
    )
    const getResult = await responseJson(getResponse)
    assertStatus(getResponse, 200, 'signed GET')

    const originalBody = JSON.stringify({ message: 'functional-e2e' })
    const postResponse = await identity.authenticatedHttp.dispatch(
      new Request(`${verifierOrigin}/functional/post`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: originalBody,
      }),
      request => fetch(request),
    )
    const postResult = await responseJson(postResponse)
    assertStatus(postResponse, 200, 'signed POST')

    const tamperedResponse = await identity.authenticatedHttp.dispatch(
      new Request(`${verifierOrigin}/functional/post`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: originalBody,
      }),
      request => fetch(new Request(request.url, {
        method: request.method,
        headers: request.headers,
        redirect: 'manual',
        body: JSON.stringify({ message: 'tampered' }),
      })),
    )
    const tamperedResult = await responseJson(tamperedResponse)
    assertStatus(tamperedResponse, 401, 'tampered POST')
    if (tamperedResult.reason !== 'Content-Digest verification failed') {
      throw new Error(`tampered POST failed for an unexpected reason: ${String(tamperedResult.reason)}`)
    }

    const result = {
      dshConsumer: CONSUMER,
      did: publicIdentity.reference.did,
      get: getResult,
      post: postResult,
      tamperedPost: tamperedResult,
    }
    await writeFile(resultPath, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 })
    return result
  } finally {
    await lease.dispose()
  }
}

async function waitForProvider(ctx) {
  const deadline = Date.now() + 10_000
  while (Date.now() < deadline) {
    const health = await ctx.anpIdentity.health()
    if (health.status !== 'unavailable') return
    await new Promise(resolve => setTimeout(resolve, 25))
  }
  throw new Error('ANP Identity provider did not become ready')
}

function requiredString(value, name) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${name} is required`)
  }
  return value
}

async function responseJson(response) {
  try {
    return await response.json()
  } catch {
    throw new Error(`verifier returned a non-JSON response with status ${response.status}`)
  }
}

function assertStatus(response, expected, label) {
  if (response.status !== expected) {
    throw new Error(`${label} returned HTTP ${response.status}, expected ${expected}`)
  }
}
