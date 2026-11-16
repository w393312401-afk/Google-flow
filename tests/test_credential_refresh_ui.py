"""Credential recovery button routing with synthetic responses only."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("node"), "Node.js required for UI checks")
class CredentialRefreshUITests(unittest.TestCase):
    def test_auth_status_routing_pending_deduplication_and_result_reload(self):
        result = subprocess.run(
            [shutil.which("node"), "-"], input=r"""
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=[...fs.readFileSync('static/manage.html','utf8').matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].at(-1)[1];
const nodes=new Map(),requests=[],toasts=[];
function node(id){if(!nodes.has(id)){const classes=new Set();nodes.set(id,{value:'',checked:false,disabled:false,innerHTML:'',textContent:'',className:'',style:{},classList:{add:(...names)=>names.forEach(name=>classes.add(name)),remove:(...names)=>names.forEach(name=>classes.delete(name)),contains:name=>classes.has(name),toggle:(name,on)=>on?classes.add(name):classes.delete(name)}})}return nodes.get(id)}
let accounts=[],respond;
const ctx={console,URLSearchParams,document:{hidden:false,getElementById:node,addEventListener(){},createElement(){const el=node('toast-'+toasts.length);toasts.push(el);return el},body:{appendChild(){},removeChild(){}}},location:{},setTimeout(){},setInterval(){return 1},clearInterval(){},fetch:async(url,opts={})=>{requests.push({url,method:opts.method||'GET'});if(opts.method==='POST')return respond(url);return {ok:true,status:200,json:async()=>url==='/api/tokens'?accounts:{}}}};
ctx.window=ctx;ctx.addEventListener=()=>{};vm.createContext(ctx);vm.runInContext(source,ctx);
const run=code=>vm.runInContext(code,ctx),postCount=()=>requests.filter(item=>item.method==='POST').length;
const invalid={id:15,email:'invalid@example.test',is_active:false,protocol_mode:'protocol',last_health_reason:'AT_REFRESH: credentials rejected (UNAUTHENTICATED)'};
const healthy={id:11,email:'valid@example.test',is_active:false,protocol_mode:'protocol',last_health_reason:'',at_expires:'2000-01-01T00:00:00Z'};
for(const reason of ['credentials rejected','credentials_rejected','authentication_failed','UNAUTHENTICATED'])assert(run(`credentialLoginRequired(${JSON.stringify({last_health_reason:reason})})`));
assert(run("credentialLoginRequired({last_health_reason:'AT_REFRESH: credential recovery required'})"));
for(const item of [healthy,{last_health_reason:'network or proxy unavailable'},{last_health_reason:'traffic restriction'},{last_health_reason:'PERMISSION_DENIED'},{is_active:false}])assert.equal(run(`credentialLoginRequired(${JSON.stringify(item)})`),false);
assert.equal(run(`formatHealth(${JSON.stringify(invalid)})`),'');
assert.match(run("formatHealth({last_health_reason:'network or proxy unavailable'})"),/代理\/网络/);
assert.match(run("formatHealth({last_health_reason:'traffic restriction'})"),/上游限流/);
assert.equal(run("refreshFailureText({error:'AT_REFRESH: network or proxy unavailable',attempts:1})"),'网络或代理不可用');
assert.match(run("refreshFailureText({error:'AT_REFRESH: credential recovery required',attempts:3})"),/登录凭证需要恢复/);
assert.doesNotMatch(run("refreshFailureText({error:'AT_REFRESH: credential recovery required',attempts:3})"),/已自动重试/);
assert.match(run("refreshFailureText({error:'AT_REFRESH: upstream transport unavailable',attempts:1})"),/上游传输暂时不可用/);
assert.match(run("formatHealth({last_health_reason:'AT_REFRESH: upstream transport unavailable'})"),/上游传输/);
assert.match(run("refreshFailureText({error:'AT_REFRESH: upstream unavailable (HTTP 503)',attempts:3})"),/HTTP 503.*已自动重试/);
assert.doesNotMatch(run("refreshFailureText({error:'AT_REFRESH: upstream unavailable (HTTP 403)',attempts:1})"),/已自动重试/);
assert.match(run("refreshFailureText({error:'AT_REFRESH: upstream validation response invalid',attempts:3})"),/余额校验响应异常.*已自动重试.*检查.*代理/);
assert.doesNotMatch(run("refreshFailureText({error:'AT_REFRESH: upstream validation response invalid SECRET_BODY',attempts:1})"),/SECRET_BODY/);
assert.match(run("formatHealth({last_health_reason:'AT_REFRESH: upstream validation response invalid'})"),/校验响应/);
assert.equal(run("credentialLoginRequired({last_health_reason:'AT_REFRESH: upstream validation response invalid'})"),false);
assert.match(run(`renderTokenActions(${JSON.stringify(invalid)})`),/text-red-600/);
assert.doesNotMatch(run(`renderTokenActions(${JSON.stringify(healthy)})`),/text-red-600/);
accounts=[invalid,healthy];ctx.syntheticAccounts=accounts;run('allTokens=syntheticAccounts;renderTokens()');
assert.doesNotMatch(node('tokenTableBody').innerHTML,/登录失效/);
(async()=>{
 let release;
 respond=()=>new Promise(resolve=>{release=resolve});
 const first=run('refreshTokenAT(15)');await run('refreshTokenAT(15)');
 assert.equal(postCount(),1);assert.equal(requests[0].url,'/api/tokens/15/recover-credentials');
 assert(run('credentialRefreshes.has(15)'));assert.match(node('tokenTableBody').innerHTML,/disabled[^>]*aria-busy="true"/);assert.match(node('tokenTableBody').innerHTML,/获取凭证中/);
 accounts=[{...invalid,last_health_reason:'',at_expires:'2099-01-01T00:00:00Z'},healthy];
 release({ok:true,status:200,json:async()=>({success:true,code:'credentials_recovered',token:{id:15,at_expires:'2099-01-01T00:00:00Z'}})});await first;
 assert.equal(run('credentialRefreshes.size'),0);assert(toasts.some(item=>item.textContent.includes('已获取并验证最新凭证')));
 assert.doesNotMatch(run('renderTokenActions(allTokens[0])'),/text-red-600/);
 respond=async()=>({ok:true,status:200,json:async()=>({success:true,token:{id:11}})});await run('refreshTokenAT(11)');assert.equal(requests.filter(item=>item.method==='POST').at(-1).url,'/api/tokens/11/refresh-at');
 accounts=[invalid,healthy];ctx.syntheticAccounts=accounts;run('allTokens=syntheticAccounts');
 respond=async()=>({ok:false,status:422,json:async()=>({detail:{success:false,code:'login_device_confirmation',message:'请在对应环境完成设备确认后重试'}})});await run('refreshTokenAT(15)');
 assert(toasts.some(item=>item.textContent.includes('完成设备确认')));assert.equal(run('credentialRefreshes.size'),0);assert.match(run('renderTokenActions(allTokens[0])'),/text-red-600/);
 respond=async()=>{throw Error('SYNTHETIC transport error')};await run('refreshTokenAT(15)');assert.equal(run('credentialRefreshes.size'),0);assert(toasts.some(item=>item.textContent.includes('请求未完成')));
 respond=async()=>({ok:false,status:401,json:async()=>({})});await run('refreshTokenAT(15)');assert.equal(ctx.location.href,'/login');assert.equal(run('credentialRefreshes.size'),0);
 const before=postCount();await run('refreshTokenAT(999)');assert.equal(postCount(),before);
 assert(requests.some(item=>item.url==='/api/tokens'&&item.method==='GET'));
 assert(requests.some(item=>item.url==='/api/stats'&&item.method==='GET'));
})().catch(error=>{console.error(error);process.exitCode=1});
""", text=True, cwd=ROOT, env={**os.environ, "TZ": "Asia/Shanghai"},
            capture_output=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
