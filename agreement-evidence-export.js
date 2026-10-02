export function agreementEvidenceMetadata(detail) {
  const { customer_url, signer_links, ...metadata } = detail;
  if (metadata.plan) {
    const { plan_agreement_url, ...plan } = metadata.plan;
    metadata.plan = plan;
  }
  return { ...metadata, observation_notice: {
    source_ip: 'Backend-observed request address. It may identify a reverse proxy rather than the signer; it is not verified customer location or identity.',
    user_agent: 'Unverified request header, supplied by a browser or intermediary. It is not proof of a particular device or person.',
    verification_method: 'The recorded method distinguishes secure-link access and authenticated staff signing. Historical observations retain their original method. Network observations do not upgrade that method.'
  } };
}

// Small dependency-free ZIP writer using stored entries. Each private database
// blob is loaded individually; the complete archive is never assembled in RAM.
const table = Uint32Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = table[(crc ^ byte) & 255] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
export async function* agreementEvidenceZIP(entries) {
  const directory = []; let offset = 0;
  for await (const entry of entries) {
    if (!/^[a-zA-Z0-9_./-]+$/.test(entry.name) || entry.name.startsWith('/') || entry.name.includes('..')) throw new Error('invalid_archive_entry');
    const name = Buffer.from(entry.name), bytes = Buffer.from(entry.bytes), crc = crc32(bytes);
    if (offset + bytes.length > 0xffffffff) throw new Error('archive_size_limit');
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50); header.writeUInt16LE(20,4); header.writeUInt16LE(0x0800,6);
    header.writeUInt16LE(33,12); // January 1, 1980; evidence timestamps live in manifest.
    header.writeUInt32LE(crc,14); header.writeUInt32LE(bytes.length,18); header.writeUInt32LE(bytes.length,22); header.writeUInt16LE(name.length,26);
    directory.push({ name, crc, length: bytes.length, offset });
    yield header; yield name; yield bytes;
    offset += header.length + name.length + bytes.length;
  }
  const centralStart = offset;
  for (const entry of directory) {
    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50); header.writeUInt16LE(20,4); header.writeUInt16LE(20,6); header.writeUInt16LE(0x0800,8); header.writeUInt16LE(33,14);
    header.writeUInt32LE(entry.crc,16); header.writeUInt32LE(entry.length,20); header.writeUInt32LE(entry.length,24); header.writeUInt16LE(entry.name.length,28); header.writeUInt32LE(entry.offset,42);
    yield header; yield entry.name; offset += header.length + entry.name.length;
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(directory.length,8); end.writeUInt16LE(directory.length,10); end.writeUInt32LE(offset-centralStart,12); end.writeUInt32LE(centralStart,16);
  yield end;
}

export async function streamAgreementEvidence({ pool, service, row, response }) {
  const signatures=(await pool.query('SELECT * FROM agreement_signatures WHERE agreement_id=$1 ORDER BY submitted_at',[row.id])).rows;
  const artifacts=(await pool.query('SELECT id,kind,asset_id,sha256,created_at FROM agreement_artifacts WHERE agreement_id=$1 ORDER BY kind',[row.id])).rows;
  const assetIDs=[...new Set([...(row.snapshot.documents||[]).map((doc)=>doc.asset_id),row.snapshot.terms_document?.asset_id].filter(Boolean))];
  const sources=(await pool.query('SELECT id,name,source_sha256,normalized_sha256,pages,created_at FROM agreement_assets WHERE company_id=$1 AND id=ANY($2::uuid[])',[row.company_id,assetIDs])).rows;
  const manifest={format_version:1,...agreementEvidenceMetadata(await service.detail(pool,row,{staff:true,includeActivity:true})),signatures,artifacts,sources,
    integrity_notice:'Application-stored hashes allow integrity comparison. They are not independent notarization or a third-party digital seal.'};
  async function* entries(){
    yield{name:'manifest.json',bytes:Buffer.from(JSON.stringify(manifest,null,2))};
    for(const artifact of artifacts){const record=(await pool.query('SELECT bytes FROM agreement_artifacts WHERE id=$1 AND agreement_id=$2',[artifact.id,row.id])).rows[0];yield{name:`documents/${artifact.kind}.pdf`,bytes:record.bytes};}
    for(const source of sources){const record=(await pool.query('SELECT original_bytes,normalized_bytes FROM agreement_assets WHERE id=$1 AND company_id=$2',[source.id,row.company_id])).rows[0];yield{name:`sources/${source.id}-original.pdf`,bytes:record.original_bytes};yield{name:`sources/${source.id}-normalized.pdf`,bytes:record.normalized_bytes};}
  }
  response.type('application/zip').set('Content-Disposition',`attachment; filename="agreement-${row.number}-evidence.zip"`);
  try {
    for await(const chunk of agreementEvidenceZIP(entries())) {
      if(response.destroyed)return;
      if(!response.write(chunk))await new Promise(resolve=>{const done=()=>{response.off('drain',done);response.off('close',done);resolve();};response.once('drain',done);response.once('close',done);});
    }
    response.end();
  } catch { response.destroy(); }
}
