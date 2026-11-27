import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {readSteinerProtocolProjection} from '../frontend/src/features/ortho/cephaloSteinerProtocol.ts';
import {readTweedMerrifieldProtocolProjection} from '../frontend/src/features/ortho/cephaloTweedMerrifieldProtocol.ts';
test('SCI05 actual HTTP response consumed by both readers',()=>{
 const data=JSON.parse(readFileSync(join(process.env.RUNNER_TEMP!,'sci05-response.json'),'utf8'));
 const s=readSteinerProtocolProjection(data),t=readTweedMerrifieldProtocolProjection(data);
 assert.equal(s?.rows.length,15);assert.equal(t?.rows.length,4);
 assert.ok([...s!.rows,...t!.rows].every(r=>r.value===12&&r.classification_authority===false));
 data.scientific_read_path.protocol_profiles.steiner.rows[0].value_authority_method_id='wrong';
 assert.equal(readSteinerProtocolProjection(data),null);
});
