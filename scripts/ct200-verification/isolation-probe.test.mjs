import assert from 'node:assert/strict';
import { validateConfig, validateFacts, readBoundedDescriptor, gpuDirectoryAbsent, rootUnavailable } from './isolation-probe.mjs';
const clone = x => JSON.parse(JSON.stringify(x));
if (process.argv.length !== 3 || process.argv[2] !== '--verify') throw new Error('usage rejected');
const c = { schema:'lb-isolation-config-v1', nonce:'a'.repeat(32), outsideRoot:`/var/tmp/lb-test-run-${'a'.repeat(32)}`, outsidePort:12345, outsideNamespaces:{pid:'pid:[10]',mnt:'mnt:[11]',net:'net:[12]'}, inputSha256:'b'.repeat(64) };
const f = {uid:[65534,65534,65534,65534],gid:[65534,65534,65534,65534],groups:[],caps:{Inh:'0000000000000000',Prm:'0000000000000000',Eff:'0000000000000000',Bnd:'0000000000000000',Amb:'0000000000000000'},noNewPrivs:1,namespaces:{pid:'pid:[20]',mnt:'mnt:[21]',net:'net:[22]'},initPidNamespace:'pid:[20]',pid:1,limits:{'memory.max':'2147483648','memory.swap.max':'0','pids.max':'128','cpu.max':'100000 100000'},inputSha256:c.inputSha256,writeControl:true,outsideAbsent:true,productionAbsent:true,rootUnavailable:true,gpuAbsent:true,inputReadonly:true,networkDenied:true};
assert.deepEqual(validateFacts(c,f),{schema:'lb-isolation-receipt-v1',nonce:c.nonce,inputSha256:c.inputSha256,pid:1,namespaces:f.namespaces,limits:f.limits});
const badConfig = [x=>x.extra=true,x=>x.schema='bad',x=>x.nonce=[],x=>x.nonce='A'.repeat(32),x=>x.outsideRoot='/tmp',x=>x.outsidePort=0,x=>x.outsidePort=65536,x=>x.outsidePort='123',x=>x.inputSha256=[],x=>x.inputSha256='b'.repeat(63),x=>x.outsideNamespaces.extra='pid:[1]'];
for(const k of ['pid','mnt','net']) badConfig.push(x=>x.outsideNamespaces[k]=`${k}:[0]`,x=>x.outsideNamespaces[k]=[],x=>x.outsideNamespaces[k]='pid:[1]\n');
for(const mutate of badConfig){const x=clone(c);mutate(x);assert.throws(()=>validateConfig(x));}
const badFacts=[x=>x.extra=true,x=>x.groups=[65534],x=>x.noNewPrivs=0,x=>x.pid=2,x=>x.initPidNamespace='pid:[99]',x=>x.inputSha256='c'.repeat(64)];
for(const k of ['uid','gid'])for(let i=0;i<4;i++)badFacts.push(x=>x[k][i]=0,x=>x[k][i]='65534');
for(const k of ['Inh','Prm','Eff','Bnd','Amb'])badFacts.push(x=>x.caps[k]='0000000000000001',x=>x.caps[k]=0);
for(const k of ['pid','mnt','net'])badFacts.push(x=>x.namespaces[k]=c.outsideNamespaces[k],x=>x.namespaces[k]='bad');
for(const k of Object.keys(f.limits))badFacts.push(x=>x.limits[k]='max',x=>x.limits[k]=Number(f.limits[k]));
for(const k of ['writeControl','outsideAbsent','productionAbsent','rootUnavailable','gpuAbsent','inputReadonly','networkDenied'])badFacts.push(x=>x[k]=false,x=>x[k]='true');
for(const mutate of badFacts){const x=clone(f);mutate(x);assert.throws(()=>validateFacts(c,x));}
for(const k of Object.keys(f)){const x=clone(f);delete x[k];assert.throws(()=>validateFacts(c,x));}
for(const k of Object.keys(c)){const x=clone(c);delete x[k];assert.throws(()=>validateConfig(x));}
const fakeRead = data => {let position=0;return {readSync(fd,b,offset,length){const n=Math.min(length,data.length-position,3);data.copy(b,offset,position,position+n);position+=n;return n;}};};
assert.equal(readBoundedDescriptor(123,8,fakeRead(Buffer.from('12345678'))).toString(),'12345678');
assert.throws(()=>readBoundedDescriptor(123,8,fakeRead(Buffer.alloc(10000))));
assert.throws(()=>readBoundedDescriptor(123,8,{readSync(){return -1;}}));
const directory = names => {let i=0;return {readSync(){return i<names.length?{name:names[i++]}:null;}};};
assert.equal(gpuDirectoryAbsent(directory(['null','zero'])),true);
for(const name of ['nvidia0','nvidiactl','dri','kfd'])assert.equal(gpuDirectoryAbsent(directory(['null',name])),false);
assert.throws(()=>gpuDirectoryAbsent(directory(Array(257).fill('null'))));
assert.throws(()=>gpuDirectoryAbsent(directory(['x'.repeat(256)])));
const rootStat = (overrides={}) => ({dev:77,ino:88,mode:0o40750,nlink:2,uid:0,gid:0,size:4096,mtimeMs:1,ctimeMs:1,
  isSymbolicLink:()=>false,isDirectory:()=>true,...overrides});
const rootIo = ({stat=rootStat(),openError='EACCES',afterStat=stat,firstMissing=false,secondMissing=false,closeError=false}={}) => {
  let lstatCount=0,opened=0,closed=0;
  return {state:()=>({lstatCount,opened,closed}),io:{
    lstatSync(path){assert.equal(path,'/root');lstatCount++;if((firstMissing&&lstatCount===1)||(secondMissing&&lstatCount===2)){const e=new Error('absent');e.code='ENOENT';throw e;}return lstatCount===1?stat:afterStat;},
    opendirSync(path){assert.equal(path,'/root');opened++;if(openError){const e=new Error('fixture open');e.code=openError;throw e;}return {closeSync(){closed++;if(closeError)throw new Error('close failed');}};},
  }};
};
const absentRoot = rootIo({firstMissing:true,secondMissing:true});
assert.equal(rootUnavailable(absentRoot.io),true);
assert.deepEqual(absentRoot.state(),{lstatCount:2,opened:0,closed:0});
const deniedRoot = rootIo();
assert.equal(rootUnavailable(deniedRoot.io),true);
assert.deepEqual(deniedRoot.state(),{lstatCount:2,opened:1,closed:0});
assert.equal(rootUnavailable(rootIo({openError:'EPERM'}).io),true);
const emptyReadableRoot = rootIo({openError:null});
assert.equal(rootUnavailable(emptyReadableRoot.io),false,'readable empty root is not unavailable');
assert.deepEqual(emptyReadableRoot.state(),{lstatCount:2,opened:1,closed:1},'successful opendir must always be closed');
for(const malformed of [
  rootStat({uid:1}),rootStat({gid:1}),rootStat({mode:0o40700}),rootStat({mode:0o100750,isDirectory:()=>false}),
  rootStat({mode:0o120750,isSymbolicLink:()=>true,isDirectory:()=>false}),
]) assert.throws(()=>rootUnavailable(rootIo({stat:malformed}).io));
assert.throws(()=>rootUnavailable(rootIo({openError:'EIO'}).io));
assert.throws(()=>rootUnavailable(rootIo({afterStat:rootStat({ino:89})}).io),'root identity swap must fail');
const initialStatError = new Error('initial lstat failed');initialStatError.code='EPERM';
assert.throws(()=>rootUnavailable({lstatSync(){throw initialStatError;}}),'unexpected initial lstat error must fail');
const afterStatError = new Error('restat failed');afterStatError.code='EIO';
let restatCalls=0;
assert.throws(()=>rootUnavailable({lstatSync(){if(++restatCalls===1)return rootStat();throw afterStatError;},opendirSync(){const e=new Error('denied');e.code='EACCES';throw e;}}),
  'unexpected post-open lstat error must fail');
const appearingRoot = rootIo({secondMissing:false});
appearingRoot.io.lstatSync = (()=>{let calls=0;return path=>{assert.equal(path,'/root');calls++;if(calls===1){const e=new Error('initially absent');e.code='ENOENT';throw e;}return rootStat();};})();
assert.throws(()=>rootUnavailable(appearingRoot.io),'a path appearing after ENOENT is a path swap');
const failedCloseRoot = rootIo({openError:null,closeError:true});
assert.throws(()=>rootUnavailable(failedCloseRoot.io));
assert.equal(failedCloseRoot.state().closed,1,'failed opendir close is still attempted exactly once');
console.log('isolation probe controls passed');
