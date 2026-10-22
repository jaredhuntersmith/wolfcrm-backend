import {fail,string,uuid} from './contract.js';

function courseID(value){return string(value,80);}
export function normalizeCourse(input){
  if(!input||typeof input!=='object'||Array.isArray(input))fail(400,'invalid_course');
  if(!Array.isArray(input.modules)||input.modules.length<1||input.modules.length>20)fail(400,'invalid_course_modules');
  const moduleIDs=new Set(),lessonIDs=new Set();let totalLessons=0;
  const modules=input.modules.map(module=>{
    if(!module||typeof module!=='object'||Array.isArray(module))fail(400,'invalid_course_module');
    const id=courseID(module?.id);if(moduleIDs.has(id))fail(400,'duplicate_module_id');moduleIDs.add(id);
    if(!Array.isArray(module.lessons)||module.lessons.length<1||module.lessons.length>30)fail(400,'invalid_course_lessons');
    totalLessons+=module.lessons.length;if(totalLessons>100)fail(400,'too_many_course_lessons');
    const lessons=module.lessons.map(lesson=>{
      if(!lesson||typeof lesson!=='object'||Array.isArray(lesson))fail(400,'invalid_course_lesson');
      const lessonID=courseID(lesson?.id);if(lessonIDs.has(lessonID))fail(400,'duplicate_lesson_id');lessonIDs.add(lessonID);
      if(!Array.isArray(lesson.prerequisites??[])||(lesson.prerequisites??[]).length>20)fail(400,'invalid_prerequisites');
      const prerequisites=(lesson.prerequisites??[]).map(courseID);
      if(new Set(prerequisites).size!==prerequisites.length||prerequisites.includes(lessonID))fail(400,'invalid_prerequisites');
      return {id:lessonID,title:string(lesson.title,200),definition_id:uuid(lesson.definition_id),version_id:uuid(lesson.version_id),
        required:lesson.required!==false,prerequisites};
    });
    return {id,title:string(module.title,200),lessons};
  });
  const byID=new Map(modules.flatMap(module=>module.lessons).map(lesson=>[lesson.id,lesson]));
  for(const lesson of byID.values())for(const dependency of lesson.prerequisites)if(!byID.has(dependency))fail(400,'unknown_prerequisite');
  const visited=new Set(),visiting=new Set();
  function visit(id){
    if(visiting.has(id))fail(400,'circular_prerequisite');
    if(visited.has(id))return;
    visiting.add(id);for(const prerequisite of byID.get(id).prerequisites)visit(prerequisite);
    visiting.delete(id);visited.add(id);
  }
  for(const id of byID.keys())visit(id);
  const progression=input.progression??'sequential';if(!['sequential','flexible'].includes(progression))fail(400,'invalid_course_progression');
  const categories=Array.isArray(input.categories)?input.categories.map(value=>string(value,60)):[];
  if(categories.length>12)fail(400,'too_many_categories');
  const estimated_minutes=input.estimated_minutes==null?null:Number(input.estimated_minutes);
  if(estimated_minutes!=null&&(!Number.isInteger(estimated_minutes)||estimated_minutes<1||estimated_minutes>100000))fail(400,'invalid_course_duration');
  const recertification_days=input.recertification_days==null?null:Number(input.recertification_days);
  if(recertification_days!=null&&(!Number.isInteger(recertification_days)||recertification_days<1||recertification_days>3650))fail(400,'invalid_recertification');
  const prerequisite_course_version_ids=input.prerequisite_course_version_ids??[];
  if(!Array.isArray(prerequisite_course_version_ids)||prerequisite_course_version_ids.length>10)
    fail(400,'invalid_course_prerequisites');
  const coursePrerequisites=prerequisite_course_version_ids.map(uuid);
  if(new Set(coursePrerequisites).size!==coursePrerequisites.length)fail(400,'duplicate_course_prerequisite');
  return {schema_version:1,title:string(input.title,200),description:string(input.description??'',5000,{required:false}),categories:[...new Set(categories)],
    cover_file_id:input.cover_file_id==null?null:uuid(input.cover_file_id),estimated_minutes,
    progression,required:input.required!==false,certificate_enabled:input.certificate_enabled===true,recertification_days,
    prerequisite_course_version_ids:coursePrerequisites,modules};
}

export function flattenLessons(course){
  let ordinal=0;return course.modules.flatMap(module=>module.lessons.map(lesson=>({...lesson,module_id:module.id,module_title:module.title,ordinal:++ordinal})));
}
