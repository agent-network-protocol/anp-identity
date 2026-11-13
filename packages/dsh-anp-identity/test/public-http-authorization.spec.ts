import {expect,it,vi,afterEach} from 'vitest'
const network=vi.hoisted(()=>({lookup:vi.fn(),send:vi.fn()}))
vi.mock('node:dns/promises',()=>({lookup:network.lookup}))
vi.mock('node:https',()=>({request:network.send}))
import {publicHttps} from '../src/public-http.js'
afterEach(()=>{network.lookup.mockReset();network.send.mockReset()})
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
