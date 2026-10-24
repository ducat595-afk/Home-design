import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const encoder=new TextEncoder();
const json=(value:unknown,status=200,origin="")=>new Response(JSON.stringify(value),{status,headers:{"Content-Type":"application/json","Cache-Control":"no-store","Access-Control-Allow-Origin":origin,"Vary":"Origin","Access-Control-Allow-Headers":"authorization,content-type","Access-Control-Allow-Methods":"POST,OPTIONS"}});
const b64=(bytes:Uint8Array)=>btoa(String.fromCharCode(...bytes)).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
const un64=(s:string)=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
const secret=(key:string)=>{const v=Deno.env.get(key);if(!v)throw Error("Missing server secret: "+key);return v};
async function mac(value:string){const key=await crypto.subtle.importKey("raw",encoder.encode(secret("SESSION_SECRET")),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return b64(new Uint8Array(await crypto.subtle.sign("HMAC",key,encoder.encode(value))))}
async function equal(a:string,b:string){const x=encoder.encode(a),y=encoder.encode(b);const h=await crypto.subtle.digest("SHA-256",x);const j=await crypto.subtle.digest("SHA-256",y);return new Uint8Array(h).every((v,i)=>v===new Uint8Array(j)[i])&&x.length===y.length}
async function authorize(req:Request){const raw=(req.headers.get("authorization")||"").replace(/^Bearer /,"");const parts=raw.split(".");if(parts.length!==2||!(await equal(await mac(parts[0]),parts[1])))throw Error("Unauthorized");const payload=JSON.parse(new TextDecoder().decode(un64(parts[0])));if(payload.exp<Date.now()||!["viewer","admin"].includes(payload.role))throw Error("Session expired");return payload.role as string}
Deno.serve(async req=>{
const allowed=secret("ALLOWED_ORIGIN");const origin=req.headers.get("origin")||"";if(origin!==allowed)return json({error:"Origin not allowed"},403,allowed);
if(req.method==="OPTIONS")return json({},200,allowed);
if(req.method!=="POST")return json({error:"Method not allowed"},405,allowed);
const action=new URL(req.url).pathname.split("/").pop();let body:any;
try{body=await req.json();if(!body||typeof body!=="object")throw Error("Invalid JSON")}catch{return json({error:"Invalid JSON"},400,allowed)}
try{
if(action==="login"){const pass=String(body.password||"");if(pass.length>256)return json({error:"Invalid credentials"},401,allowed);const admin=await equal(pass,secret("ADMIN_PASSWORD"));const viewer=admin||await equal(pass,secret("SHARED_PASSWORD"));if(!viewer)return json({error:"Invalid credentials"},401,allowed);const payload=b64(encoder.encode(JSON.stringify({role:admin?"admin":"viewer",exp:Date.now()+3600000})));return json({token:payload+"."+await mac(payload),admin},200,allowed)}
const role=await authorize(req);const db=createClient(secret("SUPABASE_URL"),secret("SUPABASE_SERVICE_ROLE_KEY"),{auth:{persistSession:false}});const bucket="private-photos";
if(action==="list"){const {data,error}=await db.storage.from(bucket).list("",{limit:1000,sortBy:{column:"created_at",order:"desc"}});if(error)throw error;const photos=[];for(const p of data||[]){if(!p.name||p.name.startsWith("."))continue;const {data:s,error:e}=await db.storage.from(bucket).createSignedUrl(p.name,300);if(!e&&s)photos.push({path:p.name,url:s.signedUrl})}return json({photos},200,allowed)}
if(role!=="admin")return json({error:"Forbidden"},403,allowed);
if(action==="upload"){const type=String(body.type||"");if(!["image/jpeg","image/png","image/webp","image/heic","image/heif"].includes(type))return json({error:"Unsupported image type"},400,allowed);const encoded=String(body.data||"");if(encoded.length>11200000)return json({error:"File too large"},413,allowed);const bytes=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));if(bytes.length>8*1024*1024)return json({error:"File too large"},413,allowed);const ext=({"image/jpeg":"jpg","image/png":"png","image/webp":"webp","image/heic":"heic","image/heif":"heif"} as Record<string,string>)[type];const path=crypto.randomUUID()+"."+ext;const {error}=await db.storage.from(bucket).upload(path,bytes,{contentType:type,upsert:false});if(error)throw error;return json({ok:true},200,allowed)}
if(action==="delete"){const path=String(body.path||"");if(!/^[0-9a-f-]{36}\.(jpg|png|webp|heic|heif)$/.test(path))return json({error:"Invalid path"},400,allowed);const {error}=await db.storage.from(bucket).remove([path]);if(error)throw error;return json({ok:true},200,allowed)}
return json({error:"Not found"},404,allowed)
}catch(e){const message=e instanceof Error?e.message:"Server error";return json({error:/Unauthorized|Session expired/.test(message)?"Session expired":"Request failed"},/Unauthorized|Session expired/.test(message)?401:500,allowed)}
});
