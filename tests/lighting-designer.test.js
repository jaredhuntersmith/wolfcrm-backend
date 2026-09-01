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
