import {mutate,loadActor,requireCapability,fail} from '../company-comms/access.js';
const keys=['comment_push','mention_push'];
export function createNotesPreferences({pool}) {
 async function get(input){const actor=await loadActor(pool,input);requireCapability(actor,'notes.view');return read(pool,actor.userId);}
 async function read(db,userId){const saved=(await db.query('SELECT settings FROM notes_preferences WHERE user_id=$1',[userId])).rows[0]?.settings||{};return Object.fromEntries(keys.map(key=>[key,saved[key]!==false]));}
 async function save(input,body){return mutate(pool,input,async(db,actor)=>{
  requireCapability(actor,'notes.view');if(!body||typeof body!=='object'||Object.keys(body).some(key=>!keys.includes(key)||typeof body[key]!=='boolean'))fail(400,'invalid_notes_preferences');
  await db.query('INSERT INTO notes_preferences(user_id,settings) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET settings=notes_preferences.settings||$2::jsonb',[actor.userId,JSON.stringify(body)]);return read(db,actor.userId);
 });}
 return {get,save};
}
