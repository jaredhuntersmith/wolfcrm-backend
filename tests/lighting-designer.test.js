import test from "node:test";
import assert from "node:assert/strict";
import {
  LightingInputError,
  assertLightingAssetKey,
  lightingAssetPrefix,
  normalizeLightingProjectInput,
  validateLightingDocument,
} from "../lighting-designer.js";

const layerID = "2d4fa2c2-cb6e-4d6f-a2e3-04c80eeffbe0";
const validDocument = () => ({ schemaVersion: 1, layers: [{ id: layerID, kind: "roofline" }] });

test("validates a versioned lighting project document", () => {
  const result = normalizeLightingProjectInput({ name: "Front house", document: validDocument() });
  assert.equal(result.name, "Front house");
  assert.equal(result.document.layers[0].kind, "roofline");
});

test("rejects unknown schema and malformed layers", () => {
  assert.throws(() => validateLightingDocument({ schemaVersion: 2, layers: [] }), LightingInputError);
  assert.throws(() => validateLightingDocument({ schemaVersion: 1, layers: [{ id: "bad", kind: "roofline" }] }), LightingInputError);
});

test("asset keys cannot cross company or project boundaries", () => {
  const prefix = lightingAssetPrefix("company-a", "project-a");
  assert.equal(assertLightingAssetKey("company-a", "project-a", `${prefix}source.jpg`), `${prefix}source.jpg`);
  assert.throws(() => assertLightingAssetKey("company-a", "project-a", "companies/company-a/lighting/project-b/source.jpg"), LightingInputError);
});


test("accepts current Swift enum envelope without inventing outer IDs", () => {
 const metadata={id:layerID,name:"Roofline",isVisible:true,isLocked:false,opacity:1,createdAt:"2026-10-20T12:00:00Z",updatedAt:"2026-10-20T12:00:00Z"};
 const doc={schemaVersion:1,assets:{},scene:{mode:"day",nightAmount:0},layers:[{kind:"roofline",payload:{metadata,points:[{x:0,y:0},{x:1,y:1}],style:{fixture:"c9",pattern:{colors:[{hex:"#FFD69B"}]},density:.5,previewScale:1,brightness:.8,glowRadius:.6,glowStrength:.7,opacity:1,patternOffset:0},overrides:[],reversed:false}}]};
 assert.deepEqual(validateLightingDocument(doc),doc);assert.equal(doc.layers[0].id,undefined);
 assert.throws(()=>validateLightingDocument({...doc,layers:[{...doc.layers[0],id:"11111111-1111-4111-8111-111111111111"}]}),LightingInputError);
 assert.throws(()=>validateLightingDocument({...doc,layers:[{kind:"roofline",payload:{metadata:{id:"broken"}}}]}),LightingInputError);
});
