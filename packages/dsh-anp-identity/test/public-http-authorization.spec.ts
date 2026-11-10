import {expect,it,vi,afterEach} from 'vitest'
const network=vi.hoisted(()=>({lookup:vi.fn(),send:vi.fn()}))
vi.mock('node:dns/promises',()=>({lookup:network.lookup}))
vi.mock('node:https',()=>({request:network.send}))
import {publicHttps} from '../src/public-http.js'
import { EventEmitter } from 'node:events'
import { Readable } from 'node:stream'
afterEach(()=>{vi.useRealTimers();vi.restoreAllMocks();network.lookup.mockReset();network.send.mockReset()})
it('checks current authorization after DNS/body and before constructing the physical request',async()=>{
  network.lookup.mockResolvedValue([{address:'8.8.8.8',family:4}])
  const assertActive=vi.fn(async()=>{throw new Error('revoked-during-dns')})
  await expect(publicHttps(new Request('https://service.example/read'),assertActive)).rejects.toThrow('revoked-during-dns')
  expect(assertActive).toHaveBeenCalledOnce();expect(network.send).not.toHaveBeenCalled()
})
it('aborts an unresolved DNS lookup without waiting for OS completion or sending',async()=>{
  network.lookup.mockReturnValue(new Promise(()=>{}))
  const controller=new AbortController();const pending=publicHttps(new Request('https://service.example/read',{signal:controller.signal}))
  controller.abort(new Error('owner-cancelled'))
  await expect(pending).rejects.toThrow('owner-cancelled');expect(network.send).not.toHaveBeenCalled()
})

it('allows a slow response within the Host deadline and marks sending only at the physical request',async()=>{
  vi.useFakeTimers()
  vi.spyOn(AbortSignal,'timeout').mockImplementation(milliseconds=>{
    const controller=new AbortController()
    setTimeout(()=>controller.abort(new DOMException('Deadline expired','TimeoutError')),milliseconds)
    return controller.signal
  })
  network.lookup.mockResolvedValue([{address:'8.8.8.8',family:4}])
  const sent=vi.fn()
  network.send.mockImplementation((_url,options,respond)=>{
    const outgoing=Object.assign(new EventEmitter(),{end(){
      expect(sent).toHaveBeenCalledOnce()
      setTimeout(()=>respond(Object.assign(Readable.from(['{}']),{statusCode:200,headers:{'content-type':'application/json'}})),12000)
    }})
    options.signal.addEventListener('abort',()=>outgoing.emit('error',new Error('aborted')))
    return outgoing
  })
  const pending=publicHttps(new Request('https://service.example/slow'),async()=>{}, {timeoutMs:20000,onSend:sent})
  expect(sent).not.toHaveBeenCalled()
  await vi.advanceTimersByTimeAsync(12000)
  const response=await pending
  expect(response.status).toBe(200)
  await response.body?.cancel()
  expect(network.send).toHaveBeenCalledOnce()
})

it('fails a configured transport deadline without retrying the physical request',async()=>{
  vi.useFakeTimers()
  vi.spyOn(AbortSignal,'timeout').mockImplementation(milliseconds=>{
    const controller=new AbortController()
    setTimeout(()=>controller.abort(new DOMException('Deadline expired','TimeoutError')),milliseconds)
    return controller.signal
  })
  network.lookup.mockResolvedValue([{address:'8.8.8.8',family:4}])
  network.send.mockImplementation((_url,options)=>{
    const outgoing=Object.assign(new EventEmitter(),{end(){}})
    options.signal.addEventListener('abort',()=>outgoing.emit('error',new Error('aborted')))
    return outgoing
  })
  const sent=vi.fn()
  const pending=publicHttps(new Request('https://service.example/slow'),async()=>{}, {timeoutMs:20000,onSend:sent})
  const outcome=expect(pending).rejects.toMatchObject({code:'http_request_timeout'})
  await vi.advanceTimersByTimeAsync(20000)
  await outcome
  expect(sent).toHaveBeenCalledOnce();expect(network.send).toHaveBeenCalledOnce()
})
