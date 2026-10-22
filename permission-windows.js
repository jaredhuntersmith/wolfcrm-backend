// Windows only restrict an existing grant. No client clock or timezone is used.
export function validatePermissionWindows(value, knownKeys) {
  const invalid=()=>{throw Object.assign(new Error('Use known capabilities, weekdays 0–6, and distinct 24-hour start/end times.'),{status:400,code:'invalid_permission_windows'});};
  if(!value||Array.isArray(value)||typeof value!=='object')invalid();
  const result={};
  for(const [key,window] of Object.entries(value)){
    if(!knownKeys.has(key)||!window||Object.keys(window).some(k=>!['days','start','end'].includes(k))||!Array.isArray(window.days)||!window.days.length||window.days.length>7||window.days.some(n=>!Number.isInteger(n)||n<0||n>6)||new Set(window.days).size!==window.days.length||!/^([01]\d|2[0-3]):[0-5]\d$/.test(window.start)||!/^([01]\d|2[0-3]):[0-5]\d$/.test(window.end)||window.start===window.end)invalid();
    result[key]={days:[...window.days].sort(),start:window.start,end:window.end};
  }
  return result;
}
export function permissionWindowOpen(window,timeZone,now=new Date()) {
  try{
    const parts=new Intl.DateTimeFormat('en-US',{timeZone,weekday:'short',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(now);
    const part=key=>parts.find(p=>p.type===key)?.value;
    const day=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].indexOf(part('weekday'));
    const time=part('hour')+':'+part('minute');
    if(window.start<window.end)return window.days.includes(day)&&time>=window.start&&time<window.end;
    return (time>=window.start&&window.days.includes(day))||(time<window.end&&window.days.includes((day+6)%7));
  }catch{return false;}
}
export function applyPermissionWindows(capabilities,windows,timeZone,now) {
  if(!windows||typeof windows!=='object')return capabilities;
  const result={...capabilities};
  for(const [key,window] of Object.entries(windows))if(key in result&&!permissionWindowOpen(window,timeZone,now))result[key]=false;
  return result;
}
