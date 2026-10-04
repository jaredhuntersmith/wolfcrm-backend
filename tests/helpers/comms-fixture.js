import {installCollaborationSchema} from '../../company-comms/collaboration-schema.js';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {startLocalPostgres} from './local-postgres.js';
import {legacyColumnsForCapabilities} from '../../permissions.js';
import {installStorageSchema} from '../../media-storage/schema.js';
import {installCommsSchema,installAssetGrants} from '../../company-comms/schema.js';
import {installPermissionGovernanceSchema} from '../../permission-governance.js';
import {loadActor} from '../../company-comms/access.js';

// Representative pre-Comms schema with actual legacy column types and constraints.
// Every caller gets a fresh local PostgreSQL cluster; no existing DB or env URL is read.
export async function createCommsFixture({migrate=true}={}) {
 const postgres=startLocalPostgres(),pool=new pg.Pool(postgres.config);
 const companies={a:randomUUID(),b:randomUUID()},ids=Object.fromEntries(['owner','alice','bob','carol','admin','foreign','disabled'].map(key=>[key,randomUUID()]));
 try{
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;
   CREATE TABLE companies(id uuid PRIMARY KEY,owner_user_id uuid,name text);
   CREATE TABLE users(id uuid PRIMARY KEY,company_id uuid REFERENCES companies(id),email text,display_name text,photo_url text,role text,deleted_at timestamptz,created_at timestamptz DEFAULT now());
   CREATE TABLE employee_permissions(user_id uuid PRIMARY KEY REFERENCES users(id),company_id uuid REFERENCES companies(id),permission_preset text DEFAULT 'technician',permission_overrides jsonb DEFAULT '{}',updated_at timestamptz DEFAULT now(),${Object.keys(legacyColumnsForCapabilities({})).map(key=>key+' boolean DEFAULT false').join(',')});
   CREATE TABLE employee_permission_audit(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),company_id uuid,employee_user_id uuid,changed_by_user_id uuid,previous_preset text,previous_overrides jsonb,new_preset text,new_overrides jsonb,created_at timestamptz DEFAULT now());
   CREATE TABLE conversations(id text PRIMARY KEY,company_id uuid,title text,is_group boolean NOT NULL DEFAULT false,created_by uuid NOT NULL REFERENCES users(id),created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),deleted_at timestamptz);
   CREATE TABLE conversation_participants(id text PRIMARY KEY,conversation_id text NOT NULL REFERENCES conversations(id),user_id uuid NOT NULL REFERENCES users(id),joined_at timestamptz NOT NULL DEFAULT now(),last_read_at timestamptz,UNIQUE(conversation_id,user_id));
   CREATE TABLE channels(id text PRIMARY KEY,company_id uuid,name text NOT NULL,description text,created_by uuid NOT NULL REFERENCES users(id),created_at timestamptz NOT NULL DEFAULT now(),archived_at timestamptz);
   CREATE TABLE messages(id text PRIMARY KEY,conversation_id text REFERENCES conversations(id),channel_id text REFERENCES channels(id),sender_id uuid NOT NULL REFERENCES users(id),body text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),deleted_at timestamptz,CHECK((conversation_id IS NOT NULL AND channel_id IS NULL) OR (conversation_id IS NULL AND channel_id IS NOT NULL)));
   CREATE TABLE message_attachments(id text PRIMARY KEY,message_id text REFERENCES messages(id),kind text,object_key text,url text,thumbnail_object_key text,thumbnail_url text,file_name text,mime_type text,byte_size integer,created_at timestamptz DEFAULT now());
   CREATE TABLE contacts(id uuid PRIMARY KEY,company_id uuid,name text,address text,deleted_at timestamptz);
   CREATE TABLE stages(id text PRIMARY KEY,company_id uuid,name text);
   CREATE TABLE opportunities(id text PRIMARY KEY,company_id uuid,contact_id text,stage_id text);
   CREATE TABLE schedule_events(id text PRIMARY KEY,company_id uuid,title text,start_at timestamptz,contact_id text,deleted_at timestamptz);
   CREATE TABLE quotes(id uuid PRIMARY KEY,company_id uuid,contact_id text,title text,total_cents integer,deleted_at timestamptz);
   CREATE TABLE todo_tasks(id text PRIMARY KEY,user_id uuid REFERENCES users(id),title text,detail text,due_date timestamptz,assignee_ids jsonb DEFAULT '[]',creator_id uuid,priority text DEFAULT 'normal',status text DEFAULT 'open',completed boolean DEFAULT false,completed_at timestamptz,completed_by uuid,updated_at timestamptz DEFAULT now());
   CREATE TABLE service_plans(id uuid PRIMARY KEY,company_id uuid,plan_name text);
   CREATE TABLE lead_notifications(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),user_id uuid NOT NULL,company_id uuid,contact_id text,title text NOT NULL,body text,delivered_at timestamptz,created_at timestamptz NOT NULL DEFAULT now());
   CREATE TABLE notifications(id text PRIMARY KEY,user_id uuid REFERENCES users(id),company_id uuid,kind text,title text,body text,data jsonb DEFAULT '{}',created_at timestamptz DEFAULT now(),read_at timestamptz,deleted_at timestamptz,requirements jsonb DEFAULT '[]',source_refs jsonb DEFAULT '[]');`);
  await pool.query('INSERT INTO companies(id,owner_user_id,name) VALUES($1,$2,$3),($4,$5,$6)',[companies.a,ids.owner,'A',companies.b,ids.foreign,'B']);
  for(const [key,user] of Object.entries(ids)){
   const company=key==='foreign'?companies.b:companies.a;
   await pool.query('INSERT INTO users(id,company_id,email,display_name,role) VALUES($1,$2,$3,$4,$5)',[user,company,key+'@example.invalid',key,['owner','foreign'].includes(key)?'employer':'employee']);
   const overrides=key==='bob'?{'pipeline.view':false}:key==='disabled'?{'communications.view':false}:{};
   await pool.query('INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,$3,$4)',[user,company,key==='admin'?'admin':'manager',JSON.stringify(overrides)]);
  }
  await installStorageSchema(pool);await installPermissionGovernanceSchema(pool);
  const migrateSchema=async()=>{await installCommsSchema(pool);await installAssetGrants(pool);await installCollaborationSchema(pool);};
  if(migrate)await migrateSchema();
  const actor=async key=>loadActor(pool,{userId:ids[key],companyId:key==='foreign'?companies.b:companies.a});
  const asset=async(owner='alice',category='document')=>{const id=randomUUID();await pool.query(`INSERT INTO stored_files(id,owner_user_id,uploaded_by_user_id,company_id,display_name,original_filename,object_key,mime_type,category,byte_size,cloud_status) VALUES($1,$2,$2,$3,$4,$4,$5,$6,$7,100,'active')`,[id,ids[owner],owner==='foreign'?companies.b:companies.a,'PRIVATE-'+id,'test/'+id,category==='image'?'image/jpeg':'application/pdf',category]);return id;};
  const close=async()=>{await pool.end();postgres.stop();};
  return {pool,postgres,companies,ids,actor,asset,migrate:migrateSchema,close};
 }catch(error){await pool.end();postgres.stop();throw error;}
}
