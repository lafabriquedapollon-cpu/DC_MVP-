// Shared CI-only lifecycle helpers.
export async function bounded(promise,ms,marker){
  let timer;
  try{
    return await Promise.race([promise,new Promise((_,reject)=>{
      timer=setTimeout(()=>reject(Error(marker)),ms);
    })]);
  }finally{clearTimeout(timer)}
}
export async function detachSession(session){
  await bounded(session.detach(),5000,'CDP_DETACH_TIMEOUT');
  console.log('R02_DESKTOP_PIPE_SESSION_DETACH_PASS');
}
export async function closeContext(context){
  await bounded(context.close(),15000,'CHROMIUM_CONTEXT_CLOSE_TIMEOUT');
  console.log('R02_DESKTOP_PIPE_CONTEXT_CLOSE_PASS');
}
