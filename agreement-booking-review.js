import { lockCompanySchedule } from './schedule-booking-guard.js';
import { QuoteContractError } from './quote-contract-domain.js';
export function installBookingReview({app,pool,service,authRequired,requireCapability}) {
  const route=action=>async(req,res)=>{
    res.set('Cache-Control','private, no-store');
    try {if(!req.companyId)throw new QuoteContractError('company_required','Select a company.',403);res.json(await action(req));}
    catch(error){if(error instanceof QuoteContractError)return res.status(error.status).json({error:error.code,message:error.message});console.error('[booking-review]',error.code||'internal');res.status(500).json({error:'booking_review_unavailable',message:'Booking confirmations could not be updated. Try again.'});}
  };
  app.get('/api/schedule/customer-bookings/pending',authRequired,requireCapability('schedule.edit'),route(async req=>({bookings:(await pool.query(`SELECT b.id,b.job_id,b.review_version,b.agreement_id,e.title,e.contact_id,e.start_at,e.end_at,c.name AS customer_name,co.timezone
    FROM agreement_bookings b JOIN schedule_events e ON e.id=b.job_id AND e.company_id=b.company_id
    LEFT JOIN contacts c ON c.id::text=e.contact_id AND c.company_id=b.company_id JOIN companies co ON co.id=b.company_id
    WHERE b.company_id=$1 AND b.status<>'canceled' AND b.confirmed_at IS NULL AND e.finished_at IS NULL
    ORDER BY e.start_at,b.created_at LIMIT 100`,[req.companyId])).rows})));
  app.post('/api/schedule/customer-bookings/:id/confirm',authRequired,requireCapability('schedule.edit'),route(async req=>{
    if(!/^[0-9a-f-]{36}$/i.test(req.params.id)||!Number.isInteger(req.body?.review_version))throw new QuoteContractError('booking_review_invalid','Reload the current booking before confirming.',400);
    const db=await pool.connect();try {
      await db.query('BEGIN');await lockCompanySchedule(db,req.companyId);
      const booking=(await db.query(`SELECT b.*,e.finished_at FROM agreement_bookings b JOIN schedule_events e ON e.id=b.job_id AND e.company_id=b.company_id WHERE b.id=$1 AND b.company_id=$2 FOR UPDATE OF b`,[req.params.id,req.companyId])).rows[0];
      if(!booking||booking.status==='canceled'||booking.finished_at)throw new QuoteContractError('booking_review_unavailable','This appointment no longer needs confirmation.',404);
      if(booking.review_version!==req.body.review_version)throw new QuoteContractError('booking_review_changed','This appointment changed. Review its new time before confirming.',409);
      if(!booking.confirmed_at){await db.query('UPDATE agreement_bookings SET confirmed_at=now(),confirmed_by=$2 WHERE id=$1',[booking.id,req.userId]);await service.event(db,booking.agreement_id,'booking_confirmed_by_business',{actor_type:'staff',actor_id:req.userId,payload:{booking_id:booking.id,job_id:booking.job_id,review_version:booking.review_version}});}
      await db.query('COMMIT');return {confirmed:true,booking_id:booking.id,review_version:booking.review_version};
    }catch(error){await db.query('ROLLBACK');throw error;}finally{db.release();}
  }));
}
