const $ = (id) => document.getElementById(id);
let authMode = "login";
const dropzone = $("dropzone"), fileInput = $("fileInput");
function bytes(n) { if (!n) return "۰ بایت"; const u=["بایت","کیلوبایت","مگابایت","گیگابایت"]; const i=Math.min(Math.floor(Math.log(n)/Math.log(1024)),3); return `${(n/1024**i).toLocaleString("fa-IR",{maximumFractionDigits:1})} ${u[i]}`; }
function msg(text, error=false) { $("message").textContent=text; $("message").className=`mt-4 text-sm ${error?"text-red-600":"text-emerald-700"}`; }
async function api(url, options={}) {
  const r=await fetch(url,{credentials:"same-origin",...options,headers:{"Content-Type":"application/json",...(options.headers||{})}});
  const data=await r.json().catch(()=>({error:"پاسخ نامعتبر از سرور"}));
  if(!r.ok) throw new Error(data.error||"درخواست ناموفق بود");
  return data;
}
function openAuth(mode) { authMode=mode; $("authTitle").textContent=mode==="login"?"ورود به حساب":"ساخت حساب جدید"; $("authSubmit").textContent=mode==="login"?"ورود":"ثبت‌نام"; $("authMessage").textContent=""; $("authModal").classList.remove("hidden"); $("authModal").classList.add("flex"); }
function closeAuth() { $("authModal").classList.add("hidden"); $("authModal").classList.remove("flex"); }
$("loginBtn").onclick=()=>openAuth("login"); $("registerBtn").onclick=()=>openAuth("register"); $("closeModal").onclick=closeAuth;
$("authForm").onsubmit=async e=>{e.preventDefault(); $("authMessage").textContent=""; try { await api(`/api/${authMode}`,{method:"POST",body:JSON.stringify({email:$("email").value,password:$("password").value})}); closeAuth(); msg("با موفقیت وارد شدی."); await refresh(); } catch(err){ $("authMessage").textContent=err.message; } };
$("chooseBtn").onclick=()=>fileInput.click(); dropzone.onclick=e=>{if(e.target.id!=="chooseBtn")fileInput.click();};
fileInput.onchange=()=>{if(fileInput.files.length)uploadFiles(fileInput.files);};
for(const ev of ["dragenter","dragover"]) dropzone.addEventListener(ev,e=>{e.preventDefault();dropzone.classList.add("drop-active");});
for(const ev of ["dragleave","drop"]) dropzone.addEventListener(ev,e=>{e.preventDefault();dropzone.classList.remove("drop-active");});
dropzone.addEventListener("drop",e=>{if(e.dataTransfer.files.length)uploadFiles(e.dataTransfer.files);});
function uploadFiles(files) {
  if(!window.currentUser){openAuth("login");msg("برای آپلود ابتدا وارد حساب شو.",true);return;}
  const data=new FormData(); for(const f of files)data.append("files",f);
  $("progressWrap").classList.remove("hidden"); $("progressBar").style.width="0%"; $("progressPercent").textContent="۰٪";
  const xhr=new XMLHttpRequest(); xhr.open("POST","/api/upload"); xhr.withCredentials=true;
  xhr.upload.onprogress=e=>{if(e.lengthComputable){const p=Math.round(e.loaded/e.total*100);$("progressBar").style.width=p+"%";$("progressPercent").textContent=p.toLocaleString("fa-IR")+"٪";$("progressText").textContent="در حال آپلود…";}};
  xhr.onload=async()=>{let result={};try{result=JSON.parse(xhr.responseText)}catch{} if(xhr.status>=200&&xhr.status<300){msg("آپلود با موفقیت انجام شد.");$("progressText").textContent="آپلود کامل شد";fileInput.value="";await refresh();}else{msg(result.error||"آپلود ناموفق بود.",true);}};
  xhr.onerror=()=>msg("ارتباط با سرور قطع شد.",true); xhr.send(data);
}
async function refresh() {
  try {
    const me=await api("/api/me");
    window.currentUser=me.user;
    if(!me.user){$("dashboard").classList.add("hidden");return;}
    $("dashboard").classList.remove("hidden"); $("userEmail").textContent=me.user.email;
    const data=await api("/api/files");
    $("storageLabel").textContent=`${bytes(data.used)} از ${bytes(data.quota)}`;
    $("storageBar").style.width=Math.min(100,data.used/data.quota*100)+"%";
    $("fileList").innerHTML="";
    if(!data.files.length){$("fileList").innerHTML='<p class="py-8 text-center text-slate-500">هنوز فایلی آپلود نکرده‌ای.</p>';return;}
    for(const f of data.files){
      const row=document.createElement("div");row.className="flex flex-col justify-between gap-3 py-4 sm:flex-row sm:items-center";
      const info=document.createElement("div");info.className="min-w-0";
      const name=document.createElement("p");name.className="break-all font-bold";name.textContent=f.name;
      const meta=document.createElement("p");meta.className="mt-1 text-xs text-slate-500";meta.textContent=`${bytes(f.size)} • ${f.type}`;
      info.append(name,meta);
      const actions=document.createElement("div");actions.className="flex flex-wrap gap-2";
      for(const [label,url] of [["لینک دانلود",f.directUrl],["صفحه اشتراک",f.shareUrl]]){
        const a=document.createElement("a");a.href=url;a.target="_blank";a.rel="noopener";a.className="rounded-lg border border-slate-300 px-3 py-2 text-sm";a.textContent=label;actions.append(a);
      }
      const copy=document.createElement("button");copy.className="rounded-lg bg-blue-50 px-3 py-2 text-sm font-semibold text-blue-700";copy.textContent="کپی لینک";
      copy.onclick=async()=>{try{await navigator.clipboard.writeText(f.directUrl);msg("لینک مستقیم کپی شد.");}catch{msg(f.directUrl);}};
      const del=document.createElement("button");del.className="rounded-lg bg-red-50 px-3 py-2 text-sm font-semibold text-red-700";del.textContent="حذف";
      del.onclick=async()=>{if(!confirm("این فایل حذف شود؟"))return;try{await api(`/api/files/${encodeURIComponent(f.id)}`,{method:"DELETE"});msg("فایل حذف شد.");await refresh();}catch(e){msg(e.message,true);}};
      actions.append(copy,del);row.append(info,actions);$("fileList").append(row);
    }
  } catch(e) { window.currentUser=null; }
}
$("logoutBtn").onclick=async()=>{try{await api("/api/logout",{method:"POST"});window.currentUser=null;msg("از حساب خارج شدی.");await refresh();}catch(e){msg(e.message,true);}};
refresh();