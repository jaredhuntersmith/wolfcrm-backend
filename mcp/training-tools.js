import {z} from 'zod';

const uuid=z.uuid(),empty=z.object({}).strict();
const query=(values)=>new URLSearchParams(Object.entries(values).filter(([,value])=>value!=null).map(([key,value])=>[key,String(value)])).toString();
const readCaps=['training.view_self'],authorCaps=['training.author'],assignCaps=['training.assign'],reviewCaps=['training.review'];

// Every operation dispatches a fixed canonical training route. The route rechecks
// company membership, recipient/supervisor scope, capabilities and pinned versions.
export function registerTrainingTools({read,write}){
  read('training_my_assignments','List only your current assignments and permitted progress; learner documents never include answer keys.',
    z.object({limit:z.number().int().min(1).max(50).default(25)}).strict(),'crm:read',readCaps,
    i=>`/api/training/mine?${query(i)}`);
  read('training_assignment','Read one assignment that you may access, including current response revision and learner-safe content.',
    z.object({id:uuid}).strict(),'crm:read',readCaps,i=>`/api/training/recipients/${i.id}`);
  read('training_assignment_history','Read the authorized audit history of one assignment.',
    z.object({id:uuid}).strict(),'crm:read',readCaps,i=>`/api/training/recipients/${i.id}/history`);
  write('training_save_responses','Save your own answers against the exact current revision; evidence files use the protected storage workflow.',
    z.object({id:uuid,expected_revision:z.number().int().positive(),responses:z.record(z.string(),z.json())}).strict(),
    'crm:write',readCaps,'PUT',i=>`/api/training/recipients/${i.id}/responses`,({id,...body})=>body);
  write('training_submit','Submit your own assignment after server validation. A manager review may still be required.',
    z.object({id:uuid,expected_revision:z.number().int().positive()}).strict(),
    'crm:write',readCaps,'POST',i=>`/api/training/recipients/${i.id}/submit`,({id,...body})=>body);
  read('training_reviews','List only submissions from employees you may supervise.',empty,'team:read',reviewCaps,'/api/training/reviews');
  read('training_managed_assignments','List only recipient progress for employees you may supervise.',
    z.object({status:z.enum(['assigned','in_progress','awaiting_review','corrections_requested','completed']).optional(),
      search:z.string().trim().max(100).optional(),limit:z.number().int().min(1).max(100).default(50)}).strict(),
    'team:read',reviewCaps,i=>`/api/training/managed?${query(i)}`);
  write('training_review','Approve or request corrections on a supervised submission using its current revision.',
    z.object({id:uuid,expected_revision:z.number().int().positive(),decision:z.enum(['approve','request_corrections']),feedback:z.string().max(2000)}).strict(),
    'crm:write',reviewCaps,'POST',i=>`/api/training/recipients/${i.id}/review`,({id,...body})=>body);
  write('training_completion_override','Record a documented verified completion override on permitted non-quiz/non-mandatory-video work.',
    z.object({id:uuid,expected_revision:z.number().int().positive(),reason:z.string().trim().min(15).max(2000)}).strict(),
    'crm:write',['training.override'],'POST',i=>`/api/training/recipients/${i.id}/override`,({id,...body})=>body);
  read('training_definitions','List your authorized assignment, form and assessment drafts.',empty,'crm:read',authorCaps,'/api/training/definitions');
  read('training_definition','Read one draft including author-only answer keys; never use this for a learner.',
    z.object({id:uuid}).strict(),'crm:read',authorCaps,i=>`/api/training/definitions/${i.id}`);
  read('training_template_export','Export an author-visible text-only template as a portable versioned JSON document.',
    z.object({id:uuid}).strict(),'crm:read',authorCaps,i=>`/api/training/definitions/${i.id}/export`);
  read('training_definition_version','Read an immutable published version of one author-visible definition.',
    z.object({definition_id:uuid,version_id:uuid}).strict(),'crm:read',authorCaps,
    i=>`/api/training/definitions/${i.definition_id}/versions/${i.version_id}`);
  write('training_template_import','Import a portable template into a new personal draft; protected media references are rejected.',
    z.object({format:z.literal('wolfcrm.training.template.v1'),document:z.json()}).strict(),
    'crm:write',authorCaps,'POST','/api/training/definitions/import');
  read('training_question_banks','List personal and company reusable quiz questions visible to the author.',
    empty,'crm:read',authorCaps,'/api/training/question-banks');
  read('training_question_bank','Read one reusable question and its author-only key.',
    z.object({id:uuid}).strict(),'crm:read',authorCaps,i=>`/api/training/question-banks/${i.id}`);
  const bankQuestion=z.object({title:z.string().trim().min(1).max(200),scope:z.enum(['personal','company']).default('personal'),
    category:z.string().max(100).optional(),source_definition_id:uuid.optional(),question:z.json()}).strict();
  write('training_question_bank_create','Save a validated reusable question; published exams keep immutable copies.',
    bankQuestion,'crm:write',authorCaps,'POST','/api/training/question-banks');
  write('training_question_bank_update','Update a reusable question at its exact revision without rewriting published exams.',
    bankQuestion.extend({id:uuid,expected_revision:z.number().int().positive()}),'crm:write',authorCaps,'PUT',
    i=>`/api/training/question-banks/${i.id}`,({id,...body})=>body);
  write('training_question_bank_archive','Archive a reusable question without altering published exams.',
    z.object({id:uuid,expected_revision:z.number().int().positive()}).strict(),'crm:write',authorCaps,'POST',
    i=>`/api/training/question-banks/${i.id}/archive`,({id,...body})=>body);
  write('training_question_bank_import','Copy a saved question and authorize its protected images for an owned draft definition.',
    z.object({id:uuid,definition_id:uuid}).strict(),'crm:write',authorCaps,'POST',
    i=>`/api/training/question-banks/${i.id}/import`,({id,...body})=>body);
  const document=z.object({kind:z.enum(['task','checklist','form','inspection','quiz']),title:z.string().trim().min(1).max(200),
    scope:z.enum(['personal','company']).optional(),category:z.string().trim().max(100).nullable().optional(),
    blocks:z.array(z.json()).max(100).optional(),requires_review:z.boolean().optional(),quiz:z.json().optional()}).strict();
  read('training_eligible_recipients','List employees within your explicit assignment scope; IDs may be used for distribution.',
    empty,'team:read',assignCaps,'/api/training/eligible-recipients');
  read('training_assignment_options','List assignment instances you may use as prerequisites for new work.',
    empty,'crm:read',assignCaps,'/api/training/assignments');
  write('training_definition_create','Create one personal or company training draft. The canonical typed document validator rejects unsupported blocks and unsafe media.',
    document,'crm:write',authorCaps,'POST','/api/training/definitions');
  write('training_definition_update','Update a draft only with its exact revision; assigned published versions remain immutable.',
    document.extend({id:uuid,expected_revision:z.number().int().positive()}),'crm:write',authorCaps,'PUT',
    i=>`/api/training/definitions/${i.id}`,({id,...body})=>body);
  write('training_definition_publish','Publish a validated immutable version from the exact current draft revision.',
    z.object({id:uuid,expected_revision:z.number().int().positive()}).strict(),'crm:write',['training.publish'],'POST',
    i=>`/api/training/definitions/${i.id}/publish`,({id,...body})=>body);
  write('training_assign','Assign a published definition to explicit permitted employees. Each recipient gets independent history and progress.',
    z.object({definition_id:uuid,version_id:uuid.optional(),recipient_ids:z.array(uuid).min(1).max(100).optional(),
      prerequisite_assignment_ids:z.array(uuid).max(20).optional(),
      audience:z.discriminatedUnion('kind',[
        z.object({kind:z.literal('company')}).strict(),
        z.object({kind:z.literal('role'),role:z.enum(['employee','employer'])}).strict(),
        ...['team','department','group'].map(kind=>z.object({kind:z.literal(kind),id:uuid}).strict())
      ]).optional(),
      due_at:z.iso.datetime({offset:true}).optional()}).strict(),'crm:write',assignCaps,'POST','/api/training/assignments',
    (i,key)=>({...i,request_key:key}));
  read('training_audience_groups','List company training teams, departments and custom groups that you may assign.',
    empty,'team:read',assignCaps,'/api/training/audience-groups');
  read('training_audience_group','Read an owner-managed training group and its employee IDs; canonical owner authorization applies.',
    z.object({id:uuid}).strict(),'team:read',assignCaps,i=>`/api/training/audience-groups/${i.id}`);
  const group=z.object({kind:z.enum(['team','department','group']),name:z.string().trim().min(1).max(120),
    member_ids:z.array(uuid).max(500)}).strict();
  write('training_audience_group_create','Create an owner-managed company training group with validated active employees.',
    group,'crm:write',assignCaps,'POST','/api/training/audience-groups');
  write('training_audience_group_update','Replace an owner-managed training group membership at its exact revision.',
    group.extend({id:uuid,expected_revision:z.number().int().positive()}),'crm:write',assignCaps,'PUT',
    i=>`/api/training/audience-groups/${i.id}`,({id,...body})=>body);
  write('training_quick_task','Create and assign a short required checklist to permitted employees.',
    z.object({title:z.string().trim().min(1).max(200),recipient_ids:z.array(uuid).min(1).max(100),
      prerequisite_assignment_ids:z.array(uuid).max(20).optional(),
      steps:z.array(z.string().trim().min(1).max(300)).max(100).default([]),
      due_at:z.iso.datetime({offset:true}).optional(),requires_review:z.boolean().default(false)}).strict(),
    'crm:write',['training.author','training.publish','training.assign'],'POST','/api/training/quick-tasks',
    (i,key)=>({...i,request_key:key}));
  read('training_my_courses','List your own course enrollments and progress.',empty,'crm:read',readCaps,'/api/training/courses/mine');
  read('training_course_drafts','List authorized course drafts and their published version counts.',empty,'crm:read',authorCaps,'/api/training/courses');
  read('training_course_draft','Read one authorized course draft and its lesson references.',
    z.object({id:uuid}).strict(),'crm:read',authorCaps,i=>`/api/training/courses/${i.id}`);
  read('training_lesson_options','List published assignment versions available as course lessons.',
    empty,'crm:read',authorCaps,'/api/training/course-lesson-options');
  read('training_course_version_options','List published course versions available as prerequisites for a new course.',
    empty,'crm:read',authorCaps,'/api/training/course-version-options');
  const courseLesson=z.object({id:z.string().min(1).max(80),title:z.string().trim().min(1).max(200),
    definition_id:uuid,version_id:uuid,required:z.boolean().optional(),prerequisites:z.array(z.string().min(1).max(80)).max(20).optional()}).strict();
  const course=z.object({title:z.string().trim().min(1).max(200),description:z.string().max(5000).optional(),
    categories:z.array(z.string().max(60)).max(12).optional(),cover_file_id:uuid.nullable().optional(),
    estimated_minutes:z.number().int().min(1).max(100000).nullable().optional(),progression:z.enum(['sequential','flexible']).optional(),
    required:z.boolean().optional(),certificate_enabled:z.boolean().optional(),
    recertification_days:z.number().int().min(1).max(3650).nullable().optional(),
    prerequisite_course_version_ids:z.array(uuid).max(10).optional(),
    modules:z.array(z.object({id:z.string().min(1).max(80),title:z.string().trim().min(1).max(200),
      lessons:z.array(courseLesson).min(1).max(30)}).strict()).min(1).max(20)}).strict();
  write('training_course_create','Create a draft course from published lessons; canonical validation rejects cycles and unknown versions.',
    course,'crm:write',authorCaps,'POST','/api/training/courses');
  write('training_course_update','Save a course draft at its exact revision without rewriting existing enrollments.',
    course.extend({id:uuid,expected_revision:z.number().int().positive()}),'crm:write',authorCaps,'PUT',
    i=>`/api/training/courses/${i.id}`,({id,...body})=>body);
  write('training_course_publish','Publish an immutable course version after validating lesson versions.',
    z.object({id:uuid,expected_revision:z.number().int().positive()}).strict(),'crm:write',['training.publish'],'POST',
    i=>`/api/training/courses/${i.id}/publish`,({id,...body})=>body);
  write('training_course_assign','Enroll explicit eligible employees in a published course.',
    z.object({course_id:uuid,version_id:uuid.optional(),recipient_ids:z.array(uuid).min(1).max(100),
      due_at:z.iso.datetime({offset:true}).optional()}).strict(),'crm:write',assignCaps,'POST','/api/training/course-enrollments',
    (i,key)=>({...i,request_key:key}));
  read('training_course_enrollment','Read one course enrollment you may access, including locked lesson state.',
    z.object({id:uuid}).strict(),'crm:read',readCaps,i=>`/api/training/course-enrollments/${i.id}`);
  write('training_lesson_start','Start only an unlocked lesson in your own enrolled course.',
    z.object({enrollment_id:uuid,lesson_id:z.string().min(1).max(80)}).strict(),'crm:write',readCaps,'POST',
    i=>`/api/training/course-enrollments/${i.enrollment_id}/lessons/${encodeURIComponent(i.lesson_id)}/start`,()=>({}));
  read('training_quiz_attempts','List your own attempts for one authorized assigned assessment.',
    z.object({recipient_id:uuid}).strict(),'crm:read',readCaps,i=>`/api/training/recipients/${i.recipient_id}/quiz/attempts`);
  write('training_quiz_start','Start or resume a server-timed assessment attempt; answer keys remain private.',
    z.object({recipient_id:uuid}).strict(),'crm:write',readCaps,'POST',
    i=>`/api/training/recipients/${i.recipient_id}/quiz/attempts`,()=>({}));
  write('training_quiz_save','Save responses on your own active attempt using its exact revision.',
    z.object({id:uuid,expected_revision:z.number().int().positive(),responses:z.record(z.string(),z.json())}).strict(),
    'crm:write',readCaps,'PUT',i=>`/api/training/quiz/attempts/${i.id}/responses`,({id,...body})=>body);
  write('training_quiz_submit','Submit your own assessment attempt for server grading.',
    z.object({id:uuid,expected_revision:z.number().int().positive()}).strict(),
    'crm:write',readCaps,'POST',i=>`/api/training/quiz/attempts/${i.id}/submit`,({id,...body})=>body);
  read('training_quiz_grader_view','Read an authorized supervised attempt with subjective answers and grading context.',
    z.object({id:uuid}).strict(),'team:read',reviewCaps,i=>`/api/training/quiz/attempts/${i.id}/grade`);
  write('training_quiz_grade','Grade subjective answers on a supervised assessment at its exact revision.',
    z.object({id:uuid,expected_revision:z.number().int().positive(),grades:z.record(z.string(),
      z.object({points:z.number().min(0),feedback:z.string().max(2000).optional()}).strict()),
      feedback:z.string().max(2000).optional()}).strict(),'crm:write',reviewCaps,'POST',
    i=>`/api/training/quiz/attempts/${i.id}/grade`,({id,...body})=>body);
  read('training_analytics','Read only permitted self or supervised training metrics; time-spent labels retain their limitations.',
    z.object({scope:z.enum(['self','managed']),employee_id:uuid.optional(),kind:z.enum(['task','checklist','form','inspection','quiz']).optional(),
      from:z.iso.datetime({offset:true}).optional(),to:z.iso.datetime({offset:true}).optional()}).strict(),
    'crm:read',readCaps,i=>`/api/training/analytics?${query(i)}`);
  read('training_my_certificates','List only your company-issued certificates.',empty,'crm:read',readCaps,'/api/training/certificates/mine');
  read('training_certificate','Read one certificate only if you own it or may supervise its employee.',
    z.object({id:uuid}).strict(),'crm:read',readCaps,i=>`/api/training/certificates/${i.id}`);
  read('training_certificate_verify','Verify a certificate code through the privacy-aware canonical route.',
    z.object({code:z.string().min(1).max(100)}).strict(),'crm:read',readCaps,
    i=>`/api/training/certificates/verify/${encodeURIComponent(i.code)}`);
  write('training_certificate_revoke','Revoke a supervised company certificate with a required audited reason.',
    z.object({id:uuid,reason:z.string().trim().min(1).max(1000)}).strict(),'crm:write',['training.certificates'],'POST',
    i=>`/api/training/certificates/${i.id}/revoke`,({id,...body})=>body);
  read('training_onboarding_policies','List owner-managed new-hire training policies.',empty,'crm:read',assignCaps,'/api/training/onboarding-policies');
  write('training_onboarding_policy_create','Create an owner-managed policy to assign a pinned published assignment to future eligible hires.',
    z.object({definition_id:uuid,version_id:uuid.optional(),due_after_days:z.number().int().min(0).max(365)}).strict(),
    'crm:write',assignCaps,'POST','/api/training/onboarding-policies',(i,key)=>({...i,request_key:key}));
  write('training_onboarding_course_policy_create','Create an owner-managed policy to enroll future eligible hires in a pinned published course.',
    z.object({course_id:uuid,course_version_id:uuid.optional(),due_after_days:z.number().int().min(0).max(365)}).strict(),
    'crm:write',assignCaps,'POST','/api/training/onboarding-policies',(i,key)=>({...i,request_key:key}));
  read('training_recurrences','List owner-managed daily or weekly training recurrence rules.',empty,'crm:read',assignCaps,'/api/training/recurrences');
  write('training_recurrence_create','Create an owner-managed daily or weekly recurrence of a pinned published version.',
    z.object({definition_id:uuid,version_id:uuid.optional(),recipient_ids:z.array(uuid).min(1).max(100),
      time_zone:z.string().min(1).max(100),interval_days:z.union([z.literal(1),z.literal(7)]),
      start_on:z.iso.date(),local_time:z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/),
      due_after_hours:z.number().int().min(0).max(8760),end_on:z.iso.date().optional()}).strict(),
    'crm:write',assignCaps,'POST','/api/training/recurrences',(i,key)=>({...i,request_key:key}));
  // Video pulse and completion endpoints are intentionally absent: they bind
  // to a live signed player session and must not be exposed as generic tools.
}
