import {z} from 'zod';
import {fault} from '../mcp/context.js';

// Curated from the official Responses file-input/vision contract. Unknown types
// fail explicitly instead of exposing a public URL or silently switching models.
export const fileFormats=Object.freeze({
 'application/pdf':{extensions:['pdf'],mode:'file',limitation:'PDF text and page images; extraction may be imperfect.'},
 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':{extensions:['docx'],mode:'file',limitation:'Text only; embedded images/charts are not extracted.'},
 'application/msword':{extensions:['doc'],mode:'file',limitation:'Text only; embedded images/charts are not extracted.'},
 'application/rtf':{extensions:['rtf'],mode:'file',limitation:'Text only.'},
 'application/vnd.oasis.opendocument.text':{extensions:['odt'],mode:'file',limitation:'Text only; embedded images are not extracted.'},
 'application/vnd.openxmlformats-officedocument.presentationml.presentation':{extensions:['pptx'],mode:'file',limitation:'Text only; embedded images/charts are not extracted.'},
 'application/vnd.ms-powerpoint':{extensions:['ppt'],mode:'file',limitation:'Text only; embedded images/charts are not extracted.'},
 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':{extensions:['xlsx'],mode:'file',limitation:'Provider examines up to the first 1,000 rows per sheet; not an exhaustive spreadsheet calculation.'},
 'application/vnd.ms-excel':{extensions:['xls'],mode:'file',limitation:'Provider examines up to the first 1,000 rows per sheet; not an exhaustive spreadsheet calculation.'},
 'image/png':{extensions:['png'],mode:'image',limitation:'Vision/OCR may misread small or rotated text.'},
 'image/jpeg':{extensions:['jpg','jpeg'],mode:'image',limitation:'Vision/OCR may misread small or rotated text.'},
 'image/webp':{extensions:['webp'],mode:'image',limitation:'Vision/OCR may misread small or rotated text.'}
});
export const fileExtractionSchema=z.object({id:z.uuid(),expected_version:z.number().int().positive(),question:z.string().trim().min(1).max(4000)}).strict();
export const fileResultShape={id:z.string().optional(),entity:z.literal('files').optional(),version:z.number().optional(),source:z.string().optional(),text:z.string().optional(),limitation:z.string().optional(),content_trust:z.literal('untrusted_file_data').optional()};
export async function prepareFile({app,actor,input}){
 if(!app.locals.mediaStorage?.readContent)throw fault(503,'storage_content_unavailable');
 const file=await app.locals.mediaStorage.contentMetadata(actor,input.id);
 const format=fileFormats[file.mime_type],extension=file.original_filename?.split('.').at(-1)?.toLowerCase();
 if(!format)throw fault(415,'file_extraction_unsupported','This format is unsupported by the selected extraction path. Audio/video require a separately configured transcription path; local-only files must be deliberately uploaded first.');
 if(!format.extensions.includes(extension))throw fault(415,'file_type_mismatch');
 if(file.version!==input.expected_version)throw fault(409,'file_changed');
 if(Number(file.byte_size)>8388608)throw fault(413,'file_too_large','File extraction supports at most 8 MiB per request.');
 return {file,format};
}
export function fileRequest(file,format,bytes){
 const data='data:'+file.mime_type+';base64,'+bytes.toString('base64');
 return format.mode==='image'?{type:'input_image',image_url:data,detail:'auto'}:{type:'input_file',filename:file.original_filename,file_data:data};
}
