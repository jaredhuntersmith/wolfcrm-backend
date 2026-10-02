import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { agreementEvidenceZIP, agreementEvidenceMetadata } from '../agreement-evidence-export.js';

test('evidence ZIP opens in the independent system unzip validator with exact byte contents', async () => {
  const directory=mkdtempSync('/tmp/wolfcrm-evidence-test-');
  try {
    const pdf=Buffer.from('%PDF-test signed artifact\n\x00\xff','latin1');
    const entries=[{name:'manifest.json',bytes:Buffer.from('{"format_version":1}')},{name:'sources/contract-original.pdf',bytes:pdf}];
    const chunks=[];for await(const chunk of agreementEvidenceZIP(entries))chunks.push(chunk);
    const archive=join(directory,'evidence.zip');writeFileSync(archive,Buffer.concat(chunks));
    const check=spawnSync('unzip',['-t',archive],{encoding:'utf8'});assert.equal(check.status,0,check.stdout+check.stderr);
    const original=spawnSync('unzip',['-p',archive,'sources/contract-original.pdf']);assert.equal(original.status,0);assert.deepEqual(original.stdout,pdf);
    await assert.rejects(async()=>{for await(const chunk of agreementEvidenceZIP([{name:'../escape',bytes:pdf}]))void chunk;},/invalid_archive_entry/);
  } finally {rmSync(directory,{recursive:true,force:true});}
});

// Exported audit evidence must not become a bundle of reusable signing links.
test('evidence metadata omits operational bearer links and qualifies network observations without mutating live detail', () => {
  const detail={id:'agreement',customer_url:'primary-secret',signer_links:[{url:'secondary-secret'}],plan:{id:'plan',plan_agreement_url:'plan-secret'},state:{signing:'submitted'}};
  const evidence=agreementEvidenceMetadata(detail);
  assert.equal(evidence.customer_url,undefined);
  assert.equal(evidence.signer_links,undefined);
  assert.equal(evidence.plan.plan_agreement_url,undefined);
  assert.equal(evidence.plan.id,'plan');
  assert.match(evidence.observation_notice.source_ip,/proxy/);
  assert.match(evidence.observation_notice.user_agent,/Unverified/);
  assert.equal(detail.customer_url,'primary-secret');
  assert.equal(detail.plan.plan_agreement_url,'plan-secret');
});
