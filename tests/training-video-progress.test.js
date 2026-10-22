import test from 'node:test';
import assert from 'node:assert/strict';
import {addCoveredInterval,contiguousPosition,coveredSeconds} from '../training/video-progress.js';

test('watched interval union does not reward replays or farthest-position jumps',()=>{
  let coverage=addCoveredInterval([],0,2,10);
  coverage=addCoveredInterval(coverage,1,2,10);
  assert.equal(coveredSeconds(coverage),2);
  coverage=addCoveredInterval(coverage,6,8,10);
  assert.equal(coveredSeconds(coverage),4);
  assert.equal(contiguousPosition(coverage),2);
  coverage=addCoveredInterval(coverage,2,6,10);
  assert.equal(coveredSeconds(coverage),8);
  assert.equal(contiguousPosition(coverage),8);
});
