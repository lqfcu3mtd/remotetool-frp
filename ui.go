package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (r *Runner) UI(token, host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if q.Host != host {
			failure(w, 403, "invalid host")
			return
		}
		if origin := q.Header.Get("Origin"); origin != "" && origin != "http://"+host {
			failure(w, 403, "invalid origin")
			return
		}
		if q.URL.Path == "/" && q.Method == "GET" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(uiHTML))
			return
		}
		if !auth(q, token) {
			failure(w, 401, "UI token required")
			return
		}
		if q.URL.Path == "/api/state" && q.Method == "GET" {
			r.mu.Lock()
			s := r.Snapshot
			s.Mappings = append([]MappingView{}, s.Mappings...)
			for i := range s.Mappings {
				s.Mappings[i].Key = ""
			}
			r.mu.Unlock()
			respond(w, 200, s)
			return
		}
		path := strings.TrimPrefix(q.URL.Path, "/api")
		if (path == "/v1/mappings" && q.Method == "POST") || (strings.HasPrefix(path, "/v1/mappings/") && (q.Method == "PATCH" || q.Method == "DELETE")) {
			var b any
			if q.Method != "DELETE" {
				var raw json.RawMessage
				if e := decode(q, &raw); e != nil {
					failure(w, 400, "invalid JSON")
					return
				}
				b = raw
			}
			var result any
			if e := r.API.call(q.Context(), q.Method, path, b, &result); e != nil {
				failure(w, 400, e.Error())
				return
			}
			respond(w, 200, result)
			return
		}
		failure(w, 404, "not found")
	})
}

const uiHTML = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RemoteTool FRP</title><style>body{font:15px system-ui;margin:30px auto;max-width:1100px;padding:0 18px;background:#f5f7fa;color:#17253d}section{background:white;border:1px solid #dfe4ed;border-radius:12px;padding:20px;margin:18px 0}input,select,button{font:inherit;padding:9px;margin:4px;border:1px solid #abb7ca;border-radius:6px}button{cursor:pointer}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #e0e4ec}small{color:#53617a}#error{color:#a42222;white-space:pre-wrap}.row{overflow:auto}</style><h1>RemoteTool · FRP</h1><p>选择现场端，将现场可达的 TCP 服务映射到本机 127.0.0.1。</p><section id="login"><label>本次启动的 UI 令牌 <input id="token" type="password" autocomplete="off"></label><button id="connect">连接</button></section><p id="error" role="alert"></p><section><strong id="control">尚未连接</strong><p id="endpoints"></p><small>端点在线 ≠ FRP 注册成功 ≠ 目标可达。目标状态来自现场 TCP 探测；不会验证应用协议。</small></section><section><h2>新建映射</h2><form id="create"><select id="endpoint" required aria-label="现场端"></select><input id="ip" placeholder="现场目标 IP，如 192.168.1.10" required><input id="port" type="number" min="1" max="65535" placeholder="目标端口" required><input id="local" type="number" min="1" max="65535" placeholder="本机端口" required><button>创建并启动</button></form><small>目标必须属于现场端与中心配置的允许网段；本机监听地址固定为 127.0.0.1。</small></section><section><h2>映射</h2><div class="row"><table><thead><tr><th>现场 / 目标</th><th>本机入口</th><th>现场在线</th><th>FRP 提供端</th><th>目标 TCP</th><th>本机访问端</th><th>操作</th></tr></thead><tbody id="rows"></tbody></table></div><p><small>访问端 configured-unverified 仅表示配置被接受，不代表端到端连接成功。停止/删除会重启本机与对应现场的 frpc，断开这些实例的现有连接；其他映射可重连。操作在后续轮询生效，离线可能延迟至租约失效。</small></p></section><script>
let token='',busy=false;
const $=id=>document.getElementById(id);
async function api(path,method='GET',body){const r=await fetch(path,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});const j=await r.json();if(!r.ok)throw Error(j.error||'请求失败');return j}
function textCell(row,text){const c=document.createElement('td');c.textContent=text;row.append(c);return c}
async function refresh(){if(!token||busy)return;busy=true;try{const s=await api('/api/state');$('control').textContent='中心连接：'+s.control;$('endpoints').textContent=(s.endpoints||[]).map(e=>(e.name||e.id)+' · '+e.presence).join(' / ');const selected=$('endpoint').value;$('endpoint').replaceChildren();for(const e of s.endpoints||[]){const o=document.createElement('option');o.value=e.id;o.textContent=(e.name||e.id)+' ('+e.presence+')';$('endpoint').append(o)}if([...$('endpoint').options].some(x=>x.value===selected))$('endpoint').value=selected;$('rows').replaceChildren();for(const m of s.mappings||[]){const row=document.createElement('tr');textCell(row,m.endpointId+' / '+m.targetIP+':'+m.targetPort);textCell(row,'127.0.0.1:'+m.localPort);textCell(row,m.endpointPresence);textCell(row,m.provider);textCell(row,m.target);textCell(row,m.visitor||'pending');const c=textCell(row,'');for(const [label,method,body]of [[m.enabled?'停止':'启动','PATCH',{enabled:!m.enabled}],['删除','DELETE',undefined]]){const b=document.createElement('button');b.textContent=label;b.onclick=async()=>{b.disabled=true;try{await api('/api/v1/mappings/'+m.id,method,body);$('error').textContent='';await refresh()}catch(e){$('error').textContent=e.message}finally{b.disabled=false}};c.append(b)}$('rows').append(row)}}catch(e){$('error').textContent=e.message}finally{busy=false}}
$('connect').onclick=()=>{token=$('token').value;$('token').value='';$('error').textContent='';refresh()};$('create').onsubmit=async e=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;try{await api('/api/v1/mappings','POST',{endpointId:$('endpoint').value,targetIP:$('ip').value.trim(),targetPort:Number($('port').value),localPort:Number($('local').value)});$('error').textContent='';await refresh()}catch(e){$('error').textContent=e.message}finally{b.disabled=false}};setInterval(refresh,2000);
</script></html>`
