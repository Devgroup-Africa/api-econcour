const express = require('express');
const axios = require('axios');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const PDFDocument = require('pdfkit');
const rateLimit = require('express-rate-limit');
const env = require('../config/env');
const { Contest, Program, ContestProgram, ProgramSubject, Subject, DocumentRequirement, Application, ApplicationDocument, Payment, Message, Notification, Grade, Candidate, Establishment, Administrator, SupportRequest, Province, EducationLevel, Session } = require('../models/mongo');
const { createApplication } = require('../services/applicationService');
const emailService = require('../services/emailService');
const { AppError, ok, asyncHandler } = require('../utils/api');
const { authenticate, scopeEstablishment, requirePasswordChanged } = require('../middleware/mongoAuth');
const { validateUploadedFiles } = require('../middleware/fileSignature');
const router = express.Router();
router.use(require('./catalog-management'));
const {router: candidateAuthRouter, authenticateCandidate, createCandidateSession} = require('./candidate-auth');
router.use(candidateAuthRouter);
router.use(['/candidats/nip/:nip', '/candidats/nipcan/:nipcan/dashboard'], authenticateCandidate, (req, res, next) => {
  if (String(req.params.nip || req.params.nipcan).trim().toUpperCase() !== req.candidate.nipcan) return next(new AppError(403, 'CANDIDATE_FORBIDDEN', 'Ce NIPCAN ne correspond pas à votre compte'));
  next();
});
router.post('/candidats', (req, res, next) => req.headers['x-candidate-token'] ? authenticateCandidate(req, res, next) : next());
router.post('/applications', authenticateCandidate, (req, res, next) => {req.body.candidateId = req.candidate._id; req.body.candidate = {firstName: req.candidate.firstName, lastName: req.candidate.lastName, phone: req.candidate.phone}; next();});
const authenticationLimiter = rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:'draft-7',legacyHeaders:false,message:{success:false,error:{code:'TOO_MANY_AUTH_ATTEMPTS'},message:'Trop de tentatives. Réessayez dans quelques minutes.'}});
const required = (...paths) => (req, _res, next) => { const missing = paths.filter(path => path.split('.').reduce((v,k) => v?.[k], req.body) == null); missing.length ? next(new AppError(422, 'VALIDATION_ERROR', 'Données invalides', missing.map(field => ({ field, message: 'Champ obligatoire' })))) : next(); };
const requireSuperAdmin=(req,_res,next)=>req.admin?.role==='super_admin'?next():next(new AppError(403,'SUPER_ADMIN_REQUIRED','Accès réservé au super-administrateur'));
const defaultPermissionsByRole = {
  admin: ['view_applications', 'manage_applications', 'view_documents', 'validate_documents', 'enter_grades', 'validate_grades', 'view_payments', 'manage_payments', 'view_reports', 'manage_messages', 'manage_subadmins'],
  admin_etablissement: ['view_applications', 'manage_applications', 'view_documents', 'validate_documents', 'enter_grades', 'validate_grades', 'view_payments', 'manage_payments', 'view_reports', 'manage_messages', 'manage_subadmins'],
  reviewer: ['view_applications', 'view_documents', 'validate_documents', 'enter_grades', 'validate_grades', 'view_payments', 'view_reports', 'manage_messages', 'manage_subadmins'],
  finance: ['view_payments']
};
const effectivePermissions = admin => admin.permissions?.length ? admin.permissions : (defaultPermissionsByRole[admin.role] || []);
const requirePermission = permission => (req, _res, next) => {
  if (req.admin?.role === 'super_admin' || effectivePermissions(req.admin).includes(permission)) return next();
  next(new AppError(403, 'PERMISSION_FORBIDDEN', 'Permission insuffisante'));
};
const assignedEstablishments = admin => admin.role === 'super_admin' ? null : (admin.establishmentIds || []);
const assertContestAccess = (admin, contest) => {
  if (admin.role !== 'super_admin' && !assignedEstablishments(admin).some(id => String(id) === String(contest.establishmentId?._id || contest.establishmentId))) throw new AppError(403, 'ESTABLISHMENT_FORBIDDEN', 'Concours non attribué');
};
const archiveExpiredContests = async () => Contest.updateMany({ closesAt: { $lt: new Date() }, status: { $in: ['open', 'closed'] } }, { $set: { status: 'archived' } });
const assertContestWritable = contest => { if (contest.status === 'archived' || (contest.closesAt && new Date(contest.closesAt) < new Date())) throw new AppError(409, 'CONTEST_ARCHIVED_READ_ONLY', 'Ce concours est archivé et accessible uniquement en consultation'); };
const scopedApplicationIds = async admin => {
  if (admin.role === 'super_admin') return null;
  const contests = await Contest.find({ establishmentId: { $in: assignedEstablishments(admin) } }).select('_id').lean();
  const applications = await Application.find({ contestId: { $in: contests.map(item => item._id) } }).select('_id').lean();
  return applications.map(item => item._id);
};
const scopedApplication = async(admin, value) => {const filter=isObjectId(value)?{_id:value}:{nupcan:String(value).trim().toUpperCase()};const application=await Application.findOne(filter).populate('contestId candidateId programId');if(!application)throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');assertContestAccess(admin,application.contestId);return application;};
const applicationReadOnly = application => application.contestId?.status==='archived'||Boolean(application.contestId?.closesAt&&new Date(application.contestId.closesAt)<new Date());
const gradeSummary = grades => {const total=grades.reduce((sum,item)=>sum+Number(item.coefficient||1),0);const points=grades.reduce((sum,item)=>sum+Number(item.score)*Number(item.coefficient||1),0);return {average:total?Number((points/total).toFixed(2)):null,totalCoefficient:total};};
const rolePermissions = {
  applications_manager: ['view_applications', 'manage_applications'], documents_validator: ['view_applications', 'view_documents', 'validate_documents'], documents_viewer: ['view_documents'],
  grades_entry: ['view_applications', 'enter_grades', 'validate_grades', 'view_reports'], grades_validator: ['view_applications', 'validate_grades'], payments_viewer: ['view_payments'], reports_viewer: ['view_reports'], messaging_agent: ['manage_messages']
};
const creatableSubAdminRoles = new Set(['grades_entry', 'documents_validator']);
const isObjectId = value => typeof value === 'string' && /^[a-f\d]{24}$/i.test(value.trim());
const idFilter = value => isObjectId(value) ? { _id: value.trim() } : { legacyId: Number(value) };
const candidatePhotoUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => cb(null, /^image\/(jpeg|png|webp)$/.test(file.mimetype))
});
const documentUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 15 },
  fileFilter: (_req, file, cb) => cb(null, /^(application\/pdf|image\/(jpeg|png|webp))$/.test(file.mimetype))
});
router.get('/health', asyncHandler(async (_req, res) => ok(res, { database: 'mongodb', status: 'ready' }, 'Service disponible')));
router.get('/sessions', asyncHandler(async (_req, res) => ok(res, [], 'Sessions chargées')));
router.post('/sessions', authenticationLimiter, authenticateCandidate, asyncHandler(async (req, res) => {
  const nupcan = String(req.body?.nupcan || '').trim().toUpperCase();
  const application = await Application.findOne({ nupcan }).select('candidateId').lean();
  if (!application || String(application.candidateId) !== String(req.candidate._id)) throw new AppError(404, 'APPLICATION_NOT_FOUND', 'Candidature introuvable');
  const token = crypto.randomBytes(32).toString('hex');
  const session = await Session.create({
    candidateId: application.candidateId,
    actorType: 'candidate',
    tokenHash: crypto.createHash('sha256').update(token).digest('hex'),
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
  });
  ok(res, { id: String(session._id), token, nupcan, expiresAt: session.expiresAt }, 'Session créée', 201);
}));
router.get('/contests', asyncHandler(async (req, res) => { const query = req.query.includeClosed === 'true' ? {} : { status: 'open' }; if (req.query.q) query.$text = { $search: String(req.query.q).slice(0, 100) }; ok(res, await Contest.find(query).populate('establishmentId educationLevelId').sort({ closesAt: -1 }).limit(Math.min(Number(req.query.limit) || 20, 100)).lean(), 'Concours disponibles'); }));
router.get('/contests/:id', asyncHandler(async (req, res) => { const item = await Contest.findById(req.params.id).populate('programIds establishmentId').lean(); if (!item) throw new AppError(404, 'CONTEST_NOT_FOUND', 'Concours introuvable'); ok(res, item); }));
const contestFilter = idFilter;
const toLegacyContest = (item, totals={}) => ({ id: String(item._id), legacyId: item.legacyId, libcnc: item.title, description_concours:item.description||'', fracnc: item.fee, debcnc: item.opensAt, fincnc: item.closesAt, stacnc: item.status==='open'?'1':'0', status:item.status, sescnc:item.session||'', type_concours:item.contestType||'autre', agecnc:item.maximumAge??35, nombre_places_total:item.totalPlaces??0, duree_formation:item.trainingDuration||'', diplome_delivre:item.awardedDiploma||'', date_publication_resultats:item.resultsPublishedAt, date_debut_cours:item.coursesStartAt, series_bac_acceptees:item.acceptedBacSeries||[], criteres_selection:item.selectionCriteria||[], modalites_inscription:item.registrationSteps||[], conditions_eligibilite:item.eligibilityConditions||[], contact_email:item.contactEmail||'', contact_telephone:item.contactPhone||'', lieu_examen:item.examLocation||'', informations_complementaires:item.additionalInformation||'', etablissement_id: item.establishmentId?.legacyId || item.establishmentId?._id || item.establishmentId, etablissement_object_id:item.establishmentId?._id, etablissement_nomets: item.establishmentId?.name||'', etablissement_nom:item.establishmentId?.name||'', niveau_id: item.educationLevelId?.legacyId || item.educationLevelId?._id || item.educationLevelId, niveau_object_id:item.educationLevelId?._id, niveau_nomniv: item.educationLevelId?.name||'', nomniv:item.educationLevelId?.name||'', filieres: item.programIds || [], total_candidatures:totals.applications||0, total_documents:totals.documents||0, total_paiements:totals.payments||0, montant_paiements:totals.amount||0 });
router.get('/concours', asyncHandler(async (req, res) => {
  const query = {};
  if (req.query.etablissement_id) {
    const establishment = await Establishment.findOne(idFilter(String(req.query.etablissement_id))).select('_id');
    if (!establishment) throw new AppError(404, 'ESTABLISHMENT_NOT_FOUND', 'Établissement introuvable');
    query.establishmentId = establishment._id;
  }
  const [items,applicationTotals,paymentTotals,documentTotals]=await Promise.all([
    Contest.find(query).populate('establishmentId educationLevelId programIds').sort({closesAt:-1}).lean(),
    Application.aggregate([{$group:{_id:'$contestId',count:{$sum:1}}}]),
    Payment.aggregate([{$lookup:{from:'applications',localField:'applicationId',foreignField:'_id',as:'application'}},{$unwind:'$application'},{$group:{_id:'$application.contestId',count:{$sum:1},amount:{$sum:'$amount'}}}]),
    ApplicationDocument.aggregate([{$lookup:{from:'applications',localField:'applicationId',foreignField:'_id',as:'application'}},{$unwind:'$application'},{$group:{_id:'$application.contestId',count:{$sum:1}}}])
  ]);
  const totals=new Map();
  for(const row of applicationTotals)totals.set(String(row._id),{applications:row.count});
  for(const row of paymentTotals)Object.assign(totals.get(String(row._id))||totals.set(String(row._id),{}).get(String(row._id)),{payments:row.count,amount:row.amount});
  for(const row of documentTotals)Object.assign(totals.get(String(row._id))||totals.set(String(row._id),{}).get(String(row._id)),{documents:row.count});
  ok(res,items.map(item=>toLegacyContest(item,totals.get(String(item._id)))),'Concours chargés');
}));
router.get('/concours/:id/filieres', asyncHandler(async (req,res)=>{const contest=await Contest.findOne(contestFilter(req.params.id)).populate('programIds').lean();if(!contest)throw new AppError(404,'CONTEST_NOT_FOUND','Concours introuvable');ok(res,(contest.programIds||[]).map(p=>({id:String(p._id),filiere_id:p.legacyId,nomfil:p.name,description:p.description})));}));
router.get('/concours/:id', asyncHandler(async (req,res)=>{const item=await Contest.findOne(contestFilter(req.params.id)).populate('establishmentId educationLevelId programIds').lean();if(!item)throw new AppError(404,'CONTEST_NOT_FOUND','Concours introuvable');const result=toLegacyContest(item);result.documents_requis=(await DocumentRequirement.find({contestId:item._id,active:true}).sort({createdAt:1}).lean()).map(requirementView);ok(res,result);}));
const parseJsonField=value=>{if(value==null||value==='')return [];if(typeof value==='string'){try{return JSON.parse(value);}catch{return [];}}return value;};
const contestInput=async body=>{const update={};if(body.libcnc!=null)update.title=String(body.libcnc).trim();if(body.description_concours!=null)update.description=String(body.description_concours);if(body.fracnc!=null)update.fee=Number(body.fracnc);if(body.debcnc)update.opensAt=new Date(body.debcnc);if(body.fincnc)update.closesAt=new Date(body.fincnc);if(body.stacnc!=null)update.status=['1',1,true,'open'].includes(body.stacnc)?'open':(body.status||'closed');const fields={sescnc:'session',type_concours:'contestType',agecnc:'maximumAge',nombre_places_total:'totalPlaces',duree_formation:'trainingDuration',diplome_delivre:'awardedDiploma',contact_email:'contactEmail',contact_telephone:'contactPhone',lieu_examen:'examLocation',informations_complementaires:'additionalInformation'};for(const [source,target] of Object.entries(fields))if(body[source]!=null)update[target]=['agecnc','nombre_places_total'].includes(source)?Number(body[source]):String(body[source]);if(body.date_publication_resultats)update.resultsPublishedAt=new Date(body.date_publication_resultats);if(body.date_debut_cours)update.coursesStartAt=new Date(body.date_debut_cours);if(body.series_bac_acceptees!=null)update.acceptedBacSeries=parseJsonField(body.series_bac_acceptees);if(body.criteres_selection!=null)update.selectionCriteria=parseJsonField(body.criteres_selection);if(body.modalites_inscription!=null)update.registrationSteps=parseJsonField(body.modalites_inscription);if(body.conditions_eligibilite!=null)update.eligibilityConditions=parseJsonField(body.conditions_eligibilite);if(body.etablissement_id!=null){const e=await Establishment.findOne(establishmentFilter(body.etablissement_id)).select('_id');if(!e)throw new AppError(422,'INVALID_ESTABLISHMENT','Établissement introuvable');update.establishmentId=e._id;}if(body.niveau_id!=null){const n=await EducationLevel.findOne(idFilter(body.niveau_id)).select('_id');if(!n)throw new AppError(422,'INVALID_LEVEL','Niveau introuvable');update.educationLevelId=n._id;}return update;};
const normalizeRequirementCode = (name, index) => `${String(name).normalize('NFD').replace(/[\u0300-\u036f]/g,'').toUpperCase().replace(/[^A-Z0-9]+/g,'_').replace(/(^_|_$)/g,'') || 'DOCUMENT'}_${index + 1}`;
const parseDocumentRequirements = value => {
  if (value == null) return null;
  let items = value;
  if (typeof items === 'string') { try { items = JSON.parse(items); } catch { throw new AppError(422,'INVALID_DOCUMENT_REQUIREMENTS','La liste des documents requis est invalide'); } }
  if (!Array.isArray(items)) throw new AppError(422,'INVALID_DOCUMENT_REQUIREMENTS','La liste des documents requis doit être un tableau');
  return items.map((item,index)=>({code:normalizeRequirementCode(item.nom||item.name,index),name:String(item.nom||item.name||'').trim(),description:String(item.description||'').trim(),validationInstructions:String(item.validationInstructions||item.instructions_validation||item.aiValidationInstructions||item.ia_indications_validation||'').trim(),rejectionInstructions:String(item.rejectionInstructions||item.instructions_rejet||item.aiRejectionRules||item.ia_indications_rejet||'').trim(),required:item.obligatoire!==false&&item.required!==false,acceptedMimeTypes:Array.isArray(item.acceptedMimeTypes)?item.acceptedMimeTypes:['application/pdf','image/jpeg','image/png','image/webp'],maxSizeBytes:Number(item.maxSizeBytes)||10*1024*1024,active:true})).filter(item=>item.name);
};
const syncDocumentRequirements = async (contestId, value) => {
  const requirements=parseDocumentRequirements(value); if(requirements===null)return;
  await DocumentRequirement.updateMany({contestId},{$set:{active:false}});
  for(const requirement of requirements)await DocumentRequirement.findOneAndUpdate({contestId,programId:null,code:requirement.code},{$set:requirement,$setOnInsert:{contestId}},{upsert:true,new:true,runValidators:true});
};
const requirementView = item => ({id:String(item._id),code:item.code,nom:item.name,description:item.description||'',instructions_validation:item.validationInstructions||'',instructions_rejet:item.rejectionInstructions||'',obligatoire:item.required,acceptedMimeTypes:item.acceptedMimeTypes||[],maxSizeBytes:item.maxSizeBytes,exemple_document:item.exampleOriginalName?{nom_fichier:item.exampleOriginalName,mime_type:item.exampleMimeType,taille:item.exampleSize}:null});
router.post('/concours',authenticate,requireSuperAdmin,required('libcnc','etablissement_id','niveau_id','documents_requis'),asyncHandler(async(req,res)=>{const requirements=parseDocumentRequirements(req.body.documents_requis);if(!requirements?.length)throw new AppError(422,'DOCUMENT_REQUIREMENTS_REQUIRED','Définissez au moins un document pour ce concours');const input=await contestInput(req.body);input.slug=`${String(input.title).normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/(^-|-$)/g,'')}-${crypto.randomBytes(4).toString('hex')}`;const item=await Contest.create(input);await syncDocumentRequirements(item._id,requirements);const result=toLegacyContest(await Contest.findById(item._id).populate('establishmentId educationLevelId programIds').lean());result.documents_requis=(await DocumentRequirement.find({contestId:item._id,active:true}).sort({createdAt:1}).lean()).map(requirementView);ok(res,result,'Concours créé',201);}));
router.put('/concours/:id',authenticate,requirePermission('manage_applications'),asyncHandler(async(req,res)=>{const current=await Contest.findOne(contestFilter(req.params.id));if(!current)throw new AppError(404,'CONTEST_NOT_FOUND','Concours introuvable');assertContestAccess(req.admin,current);assertContestWritable(current);const update=await contestInput(req.body);if(req.admin.role!=='super_admin'){delete update.establishmentId;delete update.status;}const item=await Contest.findByIdAndUpdate(current._id,{$set:update},{new:true,runValidators:true}).populate('establishmentId educationLevelId programIds').lean();await syncDocumentRequirements(item._id,req.body.documents_requis);const result=toLegacyContest(item);result.documents_requis=(await DocumentRequirement.find({contestId:item._id,active:true}).sort({createdAt:1}).lean()).map(requirementView);ok(res,result,'Concours modifié');}));
router.put('/document-requirements/:id/example', authenticate, requirePermission('manage_applications'), documentUpload.single('example'), validateUploadedFiles, asyncHandler(async (req, res) => {
  const requirement = await DocumentRequirement.findById(req.params.id).populate('contestId');
  if (!requirement) throw new AppError(404, 'DOCUMENT_REQUIREMENT_NOT_FOUND', 'Exigence documentaire introuvable');
  assertContestAccess(req.admin, requirement.contestId);
  assertContestWritable(requirement.contestId);
  if (!req.file) throw new AppError(422, 'EXAMPLE_DOCUMENT_REQUIRED', 'Un document modèle est requis');
  requirement.exampleStorageKey = `document-examples/${requirement.contestId._id}/${crypto.randomUUID()}`;
  requirement.exampleContentData = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
  requirement.exampleOriginalName = req.file.originalname;
  requirement.exampleMimeType = req.file.mimetype;
  requirement.exampleSize = req.file.size;
  await requirement.save();
  ok(res, requirementView(requirement), 'Document modèle enregistré');
}));
router.delete('/document-requirements/:id/example', authenticate, requirePermission('manage_applications'), asyncHandler(async (req, res) => {
  const requirement = await DocumentRequirement.findById(req.params.id).populate('contestId');
  if (!requirement) throw new AppError(404, 'DOCUMENT_REQUIREMENT_NOT_FOUND', 'Exigence documentaire introuvable');
  assertContestAccess(req.admin, requirement.contestId);
  requirement.exampleStorageKey = undefined;
  requirement.exampleContentData = undefined;
  requirement.exampleOriginalName = undefined;
  requirement.exampleMimeType = undefined;
  requirement.exampleSize = undefined;
  await requirement.save();
  ok(res, requirementView(requirement), 'Document modèle supprimé');
}));
router.get('/document-requirements/:id/example', asyncHandler(async (req, res) => {
  const requirement = await DocumentRequirement.findById(req.params.id).select('exampleContentData exampleOriginalName exampleMimeType');
  if (!requirement?.exampleContentData) throw new AppError(404, 'EXAMPLE_DOCUMENT_NOT_FOUND', 'Document modèle introuvable');
  const match = /^data:([^;]+);base64,(.*)$/.exec(requirement.exampleContentData);
  if (!match) throw new AppError(500, 'INVALID_EXAMPLE_DOCUMENT', 'Document modèle illisible');
  res.type(match[1]).set('Content-Disposition', `inline; filename="${String(requirement.exampleOriginalName || 'exemple').replace(/["\r\n]/g, '_')}"`).send(Buffer.from(match[2], 'base64'));
}));
router.post('/admin/ai/backfill', authenticate, requirePermission('validate_documents'), asyncHandler(async (req, res) => {
  if (!env.geminiApiKey) throw new AppError(503, 'AI_NOT_CONFIGURED', 'GEMINI_API_KEY n’est pas configurée');
  if (!req.body.contestId) throw new AppError(422, 'CONTEST_REQUIRED', 'Sélectionnez un concours');
  const contest = await Contest.findOne(contestFilter(req.body.contestId)).lean();
  if (!contest) throw new AppError(404, 'CONTEST_NOT_FOUND', 'Concours introuvable');
  assertContestAccess(req.admin, contest);
  assertContestWritable(contest);
  const after = req.body.after || null;
  const before = req.body.before ? new Date(req.body.before) : new Date();
  if ((after && (typeof after !== 'string' || !/^[a-f0-9]{24}$/i.test(after))) || !Number.isFinite(before.getTime()) || before > new Date()) throw new AppError(422, 'INVALID_AI_CURSOR', 'Paramètres de reprise invalides');
  try {
    const result = await require('../services/documentAiBackfillService').processNextDocument(contest._id, after, before);
    ok(res, { ...result, before: before.toISOString() }, result.done ? 'Traitement terminé' : 'Document traité');
  } catch (error) {
    const status = error.response?.status === 429 ? 429 : 502;
    throw new AppError(status, 'AI_BACKFILL_INTERRUPTED', 'Traitement interrompu : Gemini est indisponible. Vous pouvez reprendre ultérieurement.');
  }
}));
router.post('/admin/ai/chat', authenticate, requirePermission('manage_applications'), asyncHandler(async (req, res) => {
  if (!env.geminiApiKey) throw new AppError(503, 'AI_NOT_CONFIGURED', 'GEMINI_API_KEY n’est pas configurée');
  const contest = await Contest.findOne(contestFilter(req.body.contestId)).populate('establishmentId').lean();
  if (!contest) throw new AppError(404, 'CONTEST_NOT_FOUND', 'Concours introuvable');
  assertContestAccess(req.admin, contest);
  const requirements = await DocumentRequirement.find({ contestId: contest._id, active: true }).sort({ createdAt: 1 }).lean();
  const history = Array.isArray(req.body.history) ? req.body.history.slice(-8) : [];
  const message = String(req.body.message || '').trim();
  if (!message) throw new AppError(422, 'AI_MESSAGE_REQUIRED', 'Votre message est vide');
  const context = requirements.map(item => ({ nom: item.name, description: item.description || '', validation: item.validationInstructions || '', rejet: item.rejectionInstructions || '', modele: item.exampleOriginalName || null }));
  let response;
  try {
    for (let attempt = 0; ; attempt++) {
      try {
    response = await axios.post(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(env.geminiModel)}:generateContent`, {
      generationConfig: { temperature: 0.2 },
      systemInstruction: { parts: [{ text: `Tu es l’assistant de configuration documentaire de GabConcours. Tu aides un administrateur à définir des règles contrôlables par IA pour le concours "${contest.title}". Explique clairement tes propositions en français. Tu peux proposer des textes pour validation et rejet, mais ne prétends jamais qu’une IA prouve l’authenticité d’un document. Le contrôle automatique vérifie uniquement la lisibilité, le type, la présence d’informations et la conformité aux règles. Documents actuels : ${JSON.stringify(context)}` }] },
      contents: [
        ...history.filter(item => ['user', 'assistant'].includes(item.role)).map(item => ({ role: item.role === 'assistant' ? 'model' : 'user', parts: [{ text: String(item.content || '').slice(0, 4000) }] })),
        { role: 'user', parts: [{ text: message }] }
      ]
    }, { headers: { 'x-goog-api-key': env.geminiApiKey, 'Content-Type': 'application/json' }, timeout: 25000 });
        break;
      } catch (error) {
        if (![429, 503].includes(error.response?.status) || attempt >= 2) throw error;
        await new Promise(resolve => setTimeout(resolve, 1000 * 2 ** attempt));
      }
    }
  } catch (error) {
    if (['ECONNABORTED', 'ETIMEDOUT'].includes(error.code)) throw new AppError(504, 'AI_TIMEOUT', 'Gemini met trop de temps à répondre. Veuillez réessayer.');
    const providerStatus = error.response?.status;
    if (providerStatus === 503) throw new AppError(503, 'AI_BUSY', 'Le modèle IA est temporairement surchargé. Trois tentatives ont échoué. Réessayez dans une minute ; vos consignes sont conservées.');
    const providerCode = error.response?.data?.error?.code || error.code || 'UNKNOWN_PROVIDER_ERROR';
    const providerMessage = error.response?.data?.error?.message || error.message;
    const status = [400, 401, 403].includes(providerStatus) ? 503 : providerStatus === 429 ? 429 : 502;
    console.error(JSON.stringify({ level: 'error', code: 'AI_PROVIDER_ERROR', providerStatus, providerCode, model: env.geminiModel, message: providerMessage }));
    throw new AppError(status, 'AI_PROVIDER_ERROR', `Le service IA a refusé la demande (${providerCode}) : ${String(providerMessage).slice(0, 300)}`);
  }
  const candidate = response.data?.candidates?.[0];
  const answer = candidate?.content?.parts?.filter(part => !part.thought).map(part => part.text || '').join('').trim();
  if (candidate?.finishReason !== 'STOP' || !answer) throw new AppError(502, 'AI_EMPTY_RESPONSE', 'Gemini n’a pas pu produire de réponse complète. Réessayez.');
  ok(res, { answer: answer.slice(0, 6000) }, 'Réponse IA générée');
}));
router.delete('/concours/:id',authenticate,requireSuperAdmin,asyncHandler(async(req,res)=>{const item=await Contest.findOneAndUpdate(contestFilter(req.params.id),{$set:{status:'archived'}},{new:true});if(!item)throw new AppError(404,'CONTEST_NOT_FOUND','Concours introuvable');ok(res,{id:String(item._id),status:item.status},'Concours archivé');}));
router.get('/filieres', asyncHandler(async (_req,res)=>ok(res,(await Program.find().lean()).map(p=>({id:p.legacyId||String(p._id),_id:p._id,nomfil:p.name,description:p.description,niveau_id:p.educationLevelId})),'Filières chargées')));
const contestProgramView = link => ({ id: String(link._id), concours_id: link.contestId?.legacyId || String(link.contestId?._id || link.contestId), filiere_id: link.programId?.legacyId || String(link.programId?._id || link.programId), nomfil: link.programId?.name || '', niveau_id: link.programId?.educationLevelId?.legacyId || link.programId?.educationLevelId?._id, niveau_nomniv: link.programId?.educationLevelId?.name || '', places_disponibles: link.capacity || 0, active: link.active !== false });
router.get('/concours-filieres/concours/:concoursId', authenticate, asyncHandler(async(req,res)=>{const contest=await Contest.findOne(contestFilter(req.params.concoursId)).lean();if(!contest)throw new AppError(404,'CONTEST_NOT_FOUND','Concours introuvable');assertContestAccess(req.admin,contest);const links=await ContestProgram.find({contestId:contest._id,active:true}).populate({path:'programId',populate:{path:'educationLevelId'}}).populate('contestId').sort({createdAt:1}).lean();ok(res,links.map(contestProgramView),'Filières du concours chargées');}));
router.post('/concours-filieres', authenticate, requireSuperAdmin, asyncHandler(async(req,res)=>{const contest=await Contest.findOne(contestFilter(req.body.concours_id));const program=await Program.findOne(idFilter(req.body.filiere_id));if(!contest||!program)throw new AppError(422,'INVALID_CONTEST_PROGRAM','Concours ou filière introuvable');const link=await ContestProgram.findOneAndUpdate({contestId:contest._id,programId:program._id},{contestId:contest._id,programId:program._id,establishmentId:contest.establishmentId,educationLevelId:contest.educationLevelId,capacity:Math.max(0,Number(req.body.places_disponibles)||0),active:true},{upsert:true,new:true,runValidators:true}).populate('contestId programId');await Contest.updateOne({_id:contest._id},{$addToSet:{programIds:program._id}});ok(res,contestProgramView(link),'Filière ajoutée au concours',201);}));
router.put('/concours-filieres/:id', authenticate, requireSuperAdmin, asyncHandler(async(req,res)=>{const link=await ContestProgram.findByIdAndUpdate(req.params.id,{$set:{capacity:Math.max(0,Number(req.body.places_disponibles)||0)}},{new:true,runValidators:true}).populate('contestId programId');if(!link)throw new AppError(404,'CONTEST_PROGRAM_NOT_FOUND','Association concours-filière introuvable');ok(res,contestProgramView(link),'Association mise à jour');}));
router.post('/concours-filieres/concours/:concoursId/bulk', authenticate, requireSuperAdmin, asyncHandler(async(req,res)=>{if(!Array.isArray(req.body.filieres))throw new AppError(422,'INVALID_PROGRAM_LIST','La liste des filières est invalide');const contest=await Contest.findOne(contestFilter(req.params.concoursId));if(!contest)throw new AppError(404,'CONTEST_NOT_FOUND','Concours introuvable');const resolved=[];for(const input of req.body.filieres){const program=await Program.findOne(idFilter(input.filiere_id)).select('_id');if(!program)throw new AppError(422,'INVALID_PROGRAM',`Filière introuvable : ${input.filiere_id}`);resolved.push({programId:program._id,capacity:Math.max(0,Number(input.places_disponibles)||0)});}await ContestProgram.deleteMany({contestId:contest._id});if(resolved.length)await ContestProgram.insertMany(resolved.map(item=>({contestId:contest._id,programId:item.programId,establishmentId:contest.establishmentId,educationLevelId:contest.educationLevelId,capacity:item.capacity,active:true})));contest.programIds=resolved.map(item=>item.programId);await contest.save();ok(res,{count:resolved.length},`${resolved.length} filière(s) associée(s) au concours`);}));
router.delete('/concours-filieres/:id', authenticate, requireSuperAdmin, asyncHandler(async(req,res)=>{const link=await ContestProgram.findByIdAndDelete(req.params.id);if(!link)throw new AppError(404,'CONTEST_PROGRAM_NOT_FOUND','Association concours-filière introuvable');await Contest.updateOne({_id:link.contestId},{$pull:{programIds:link.programId}});ok(res,{id:String(link._id)},'Association supprimée');}));
router.get('/filieres/:id/matieres',asyncHandler(async(req,res)=>{const program=await Program.findOne(idFilter(req.params.id)).populate('educationLevelId').lean();if(!program)throw new AppError(404,'PROGRAM_NOT_FOUND','Filière introuvable');const contest=req.query.concours_id?await Contest.findOne(contestFilter(req.query.concours_id)).lean():null;if(req.query.concours_id&&!contest)throw new AppError(422,'INVALID_CONTEST','Concours introuvable');const links=await ProgramSubject.find({programId:program._id,contestId:contest?._id||null}).populate('subjectId').lean();ok(res,{id:program.legacyId||String(program._id),_id:program._id,nomfil:program.name,niveau_id:program.educationLevelId?.legacyId||program.educationLevelId?._id,niveau_nom:program.educationLevelId?.name||'',matieres:links.map(l=>({id:l.subjectId?.legacyId||String(l.subjectId?._id),_id:l.subjectId?._id,nom_matiere:l.subjectId?.name||'',code:l.subjectId?.code||'',coefficient:l.coefficient,obligatoire:l.required}))},'Filière et matières chargées');}));
router.get('/filiere-matieres/filiere/:filiereId', authenticate, asyncHandler(async(req,res)=>{const program=await Program.findOne(idFilter(req.params.filiereId));if(!program)throw new AppError(404,'PROGRAM_NOT_FOUND','Filière introuvable');const links=await ProgramSubject.find({programId:program._id, ...(req.query.concours_id?{contestId:contestFilter(req.query.concours_id)}:{})}).populate('subjectId').lean();ok(res,links.map(link=>({id:String(link._id),filiere_id:program.legacyId||String(program._id),matiere_id:link.subjectId?.legacyId||String(link.subjectId?._id),nom_matiere:link.subjectId?.name||'',coefficient:link.coefficient,obligatoire:link.required})),'Matières de la filière chargées');}));
router.get('/filiere-matieres/coefficients/:filiereId', authenticate, asyncHandler(async(req,res)=>{const program=await Program.findOne(idFilter(req.params.filiereId)).select('_id');if(!program)throw new AppError(404,'PROGRAM_NOT_FOUND','Filière introuvable');const links=await ProgramSubject.find({programId:program._id});ok(res,{total_coefficients:links.reduce((sum,item)=>sum+Number(item.coefficient||0),0),nombre_matieres:links.length,matieres_obligatoires:links.filter(item=>item.required).length},'Coefficients calculés');}));
router.post('/filiere-matieres', authenticate, requireSuperAdmin, asyncHandler(async(req,res)=>{const program=await Program.findOne(idFilter(req.body.filiere_id));const subject=await Subject.findOne(idFilter(req.body.matiere_id));if(!program||!subject)throw new AppError(422,'INVALID_PROGRAM_SUBJECT','Filière ou matière introuvable');const contestId=req.body.concours_id? (await Contest.findOne(contestFilter(req.body.concours_id)))?._id : undefined;const link=await ProgramSubject.findOneAndUpdate({programId:program._id,subjectId:subject._id,contestId:contestId||null},{programId:program._id,subjectId:subject._id,contestId,coefficient:Number(req.body.coefficient)||1,required:req.body.obligatoire!==false},{upsert:true,new:true,runValidators:true}).populate('subjectId');ok(res,{id:String(link._id),filiere_id:program.legacyId||String(program._id),matiere_id:subject.legacyId||String(subject._id),nom_matiere:subject.name,coefficient:link.coefficient,obligatoire:link.required},'Matière associée à la filière',201);}));
router.put('/filiere-matieres/:id', authenticate, requireSuperAdmin, asyncHandler(async(req,res)=>{const link=await ProgramSubject.findByIdAndUpdate(req.params.id,{$set:{coefficient:Number(req.body.coefficient)||1,required:req.body.obligatoire!==false}},{new:true,runValidators:true}).populate('subjectId programId');if(!link)throw new AppError(404,'PROGRAM_SUBJECT_NOT_FOUND','Association filière-matière introuvable');ok(res,{id:String(link._id),coefficient:link.coefficient,obligatoire:link.required},'Matière mise à jour');}));
router.delete('/filiere-matieres/:id', authenticate, requireSuperAdmin, asyncHandler(async(req,res)=>{const link=await ProgramSubject.findByIdAndDelete(req.params.id);if(!link)throw new AppError(404,'PROGRAM_SUBJECT_NOT_FOUND','Association filière-matière introuvable');ok(res,{id:String(link._id)},'Matière retirée de la filière');}));
const establishmentFilter = idFilter;
const resolveProvinceId = async value => {
  if (value == null || value === '') return undefined;
  const province = await Province.findOne(idFilter(value)).select('_id').lean();
  if (!province) throw new AppError(422, 'INVALID_PROVINCE', 'Province introuvable');
  return province._id;
};
const toLegacyEstablishment = e => ({ id: e.legacyId || String(e._id), _id: e._id, nomets: e.name, nom: e.name, adretes: e.address || '', telefs: e.phone || '', maiets: e.email || '', code: e.code, province_id: e.provinceId?.legacyId || e.provinceId, province: e.provinceId?.name || '', ville: '', statut: e.active ? 'actif' : 'inactif', active: e.active, created_at: e.createdAt, updated_at: e.updatedAt });
router.get('/etablissements',asyncHandler(async(_req,res)=>{const items=await Establishment.find().populate('provinceId').sort({name:1}).lean();ok(res,items.map(toLegacyEstablishment),'Établissements chargés');}));
router.post('/etablissements', authenticate, requireSuperAdmin, required('nomets'), asyncHandler(async (req, res) => {
  const establishment = await Establishment.create({ name: String(req.body.nomets).trim(), address: req.body.adretes, phone: req.body.telefs, email: req.body.maiets, code: req.body.code, provinceId: await resolveProvinceId(req.body.province_id) });
  ok(res, toLegacyEstablishment(await establishment.populate('provinceId')), 'Établissement créé', 201);
}));
router.put('/etablissements/:id', authenticate, requireSuperAdmin, asyncHandler(async (req, res) => {
  const update = {};
  if (req.body.nomets != null) update.name = String(req.body.nomets).trim();
  if (req.body.adretes != null) update.address = req.body.adretes;
  if (req.body.telefs != null) update.phone = req.body.telefs;
  if (req.body.maiets != null) update.email = req.body.maiets;
  if (req.body.code != null) update.code = req.body.code;
  if (req.body.province_id != null) update.provinceId = await resolveProvinceId(req.body.province_id);
  if (req.body.active != null) update.active = Boolean(req.body.active);
  const establishment = await Establishment.findOneAndUpdate(establishmentFilter(req.params.id), { $set: update }, { new: true, runValidators: true }).populate('provinceId').lean();
  if (!establishment) throw new AppError(404, 'ESTABLISHMENT_NOT_FOUND', 'Établissement introuvable');
  ok(res, toLegacyEstablishment(establishment), 'Établissement modifié');
}));
router.delete('/etablissements/:id', authenticate, requireSuperAdmin, asyncHandler(async (req, res) => {
  const establishment = await Establishment.findOneAndUpdate(establishmentFilter(req.params.id), { $set: { active: false } }, { new: true }).populate('provinceId').lean();
  if (!establishment) throw new AppError(404, 'ESTABLISHMENT_NOT_FOUND', 'Établissement introuvable');
  ok(res, toLegacyEstablishment(establishment), 'Établissement désactivé');
}));
const toLegacyProvince = province => ({ id: province.legacyId || String(province._id), _id: province._id, nompro: province.name, nom: province.name, cdepro: province.code, code: province.code, active: province.active });
router.get('/provinces', asyncHandler(async (_req, res) => ok(res, (await Province.find({ active: true }).sort({ name: 1 }).lean()).map(toLegacyProvince), 'Provinces chargées')));
const toLegacyLevel = level => ({ id: level.legacyId || String(level._id), _id: level._id, nomniv: level.name, nom: level.name, code: level.code, description: level.description || '', rank: level.rank, active: level.active, created_at: level.createdAt, updated_at: level.updatedAt });
router.get('/niveaux', asyncHandler(async (_req, res) => ok(res, (await EducationLevel.find({ active: true }).sort({ rank: 1, name: 1 }).lean()).map(toLegacyLevel), 'Niveaux chargés')));
router.post('/niveaux', authenticate, requireSuperAdmin, required('nomniv'), asyncHandler(async (req, res) => {
  const name = String(req.body.nomniv).trim();
  const level = await EducationLevel.create({ name, code: String(req.body.code || name).trim(), description: req.body.description, rank: req.body.rank });
  ok(res, toLegacyLevel(level.toObject()), 'Niveau créé', 201);
}));
router.put('/niveaux/:id', authenticate, requireSuperAdmin, asyncHandler(async (req, res) => {
  const filter = idFilter(req.params.id);
  const update = {};
  if (req.body.nomniv != null) update.name = String(req.body.nomniv).trim();
  if (req.body.code != null) update.code = String(req.body.code).trim();
  if (req.body.description != null) update.description = String(req.body.description).trim();
  if (req.body.rank != null) update.rank = req.body.rank;
  if (req.body.active != null) update.active = Boolean(req.body.active);
  const level = await EducationLevel.findOneAndUpdate(filter, { $set: update }, { new: true, runValidators: true }).lean();
  if (!level) throw new AppError(404, 'LEVEL_NOT_FOUND', 'Niveau introuvable');
  ok(res, toLegacyLevel(level), 'Niveau modifié');
}));
router.delete('/niveaux/:id', authenticate, requireSuperAdmin, asyncHandler(async (req, res) => {
  const filter = idFilter(req.params.id);
  const level = await EducationLevel.findOneAndUpdate(filter, { $set: { active: false } }, { new: true }).lean();
  if (!level) throw new AppError(404, 'LEVEL_NOT_FOUND', 'Niveau introuvable');
  ok(res, toLegacyLevel(level), 'Niveau désactivé');
}));
router.post('/admin/auth/login', authenticationLimiter, required('email','password'), asyncHandler(async (req,res)=>{
  const email=String(req.body.email).trim().toLowerCase();
  const admin=await Administrator.findOne({email,active:true}).select('+passwordHash').populate('establishmentIds').lean();
  if(!admin||!await bcrypt.compare(String(req.body.password),admin.passwordHash))throw new AppError(401,'INVALID_CREDENTIALS','Email ou mot de passe incorrect');
  if(!env.jwtSecret)throw new AppError(503,'AUTH_NOT_CONFIGURED',"L'authentification n'est pas configurée");
  const token=jwt.sign({sub:String(admin._id),role:admin.role},env.jwtSecret,{expiresIn:process.env.JWT_EXPIRES_IN||'24h'});
  await Administrator.updateOne({_id:admin._id},{$set:{lastLoginAt:new Date()}});
  res.cookie('admin_session',token,{httpOnly:true,secure:env.nodeEnv==='production',sameSite:'lax',maxAge:24*60*60*1000,path:'/'});
  const establishment=admin.establishmentIds?.[0];
  ok(res,{token,admin:{id:String(admin._id),legacyId:admin.legacyId,nom:admin.lastName,prenom:admin.firstName,email:admin.email,role:admin.role,admin_role:admin.subAdminRole||(admin.role==='finance'?'paiements':'documents'),subAdminRole:admin.subAdminRole,permissions:effectivePermissions(admin),mustChangePassword:Boolean(admin.mustChangePassword),etablissement_id:establishment?.legacyId||establishment?._id,etablissement_object_id:establishment?._id,etablissement_nom:establishment?.name}},'Connexion réussie');
}));
router.post('/admin/auth/logout',(_req,res)=>{res.clearCookie('admin_session',{path:'/'});ok(res,null,'Déconnexion réussie')});
router.put('/admin/auth/password', authenticate, required('current_password','new_password'), asyncHandler(async(req,res)=>{const admin=await Administrator.findById(req.admin._id).select('+passwordHash');if(!admin||!await bcrypt.compare(String(req.body.current_password),admin.passwordHash))throw new AppError(422,'CURRENT_PASSWORD_INVALID','Le mot de passe actuel est incorrect');const next=String(req.body.new_password);if(next.length<10||!/[A-Z]/.test(next)||!/[a-z]/.test(next)||!/[0-9]/.test(next))throw new AppError(422,'WEAK_PASSWORD','Utilisez au moins 10 caractères avec majuscule, minuscule et chiffre');admin.passwordHash=await bcrypt.hash(next,12);admin.mustChangePassword=false;admin.passwordChangedAt=new Date();await admin.save();ok(res,{mustChangePassword:false},'Mot de passe modifié');}));
router.use('/admin', authenticate, requirePasswordChanged);
router.get('/statistics',authenticate,requirePasswordChanged,asyncHandler(async(req,res)=>{
  await archiveExpiredContests();
  const contestScope=req.admin.role==='super_admin'?{}:{establishmentId:{$in:assignedEstablishments(req.admin)}};
  const scopedContests=await Contest.find(contestScope).select('_id').lean(),contestIds=scopedContests.map(c=>c._id),appScope={contestId:{$in:contestIds}},apps=await Application.find(appScope).select('_id candidateId').lean(),appIds=apps.map(a=>a._id),candidateIds=[...new Set(apps.map(a=>String(a.candidateId)))];
  const [candidates,applications,contests,openContests,documents,payments,messages,paidAgg]=await Promise.all([Candidate.countDocuments({_id:{$in:candidateIds}}),Application.countDocuments(appScope),Contest.countDocuments(contestScope),Contest.countDocuments({...contestScope,status:'open'}),ApplicationDocument.countDocuments({applicationId:{$in:appIds}}),Payment.countDocuments({applicationId:{$in:appIds}}),Message.countDocuments({applicationId:{$in:appIds}}),Payment.aggregate([{$match:{applicationId:{$in:appIds},status:'paid'}},{$group:{_id:null,total:{$sum:'$amount'},count:{$sum:1}}}])]);
  const [approvedDocs,rejectedDocs,pendingDocs,approvedApps,pendingApps,unreadMessages]=await Promise.all([ApplicationDocument.countDocuments({applicationId:{$in:appIds},status:'approved'}),ApplicationDocument.countDocuments({applicationId:{$in:appIds},status:'rejected'}),ApplicationDocument.countDocuments({applicationId:{$in:appIds},status:{$in:['uploaded','under_review','pending']}}),Application.countDocuments({...appScope,status:'approved'}),Application.countDocuments({...appScope,status:{$in:['draft','submitted','under_review']}}),Message.countDocuments({applicationId:{$in:appIds},readAt:null,senderType:'candidate'})]);
  ok(res,{totalConcours:contests,concours:{total:contests,ouverts:openContests,fermes:contests-openContests},totalCandidatures:applications,totalCandidats:candidates,candidats:{total:candidates,complets:approvedApps,en_attente:pendingApps,validation_admin:await Application.countDocuments({status:'under_review'})},documents:{total:documents,en_attente:pendingDocs,valides:approvedDocs,rejetes:rejectedDocs},paiements:{total:payments,valides:paidAgg[0]?.count||0,en_attente:await Payment.countDocuments({status:{$in:['pending','processing']}}),montant_total:paidAgg[0]?.total||0},messages:{total:messages,non_lus:unreadMessages}},'Statistiques réelles');
}));
router.get('/admin/etablissement/:establishmentId/concours',authenticate,asyncHandler(async(req,res)=>{const id=req.params.establishmentId;const establishment=await Establishment.findOne(establishmentFilter(id)).lean();if(!establishment)throw new AppError(404,'ESTABLISHMENT_NOT_FOUND','Établissement introuvable');if(req.admin.role!=='super_admin'&&!req.admin.establishmentIds.some(assigned=>assigned.equals(establishment._id)))throw new AppError(403,'ESTABLISHMENT_FORBIDDEN','Établissement non attribué');const items=await Contest.find({establishmentId:establishment._id}).populate('educationLevelId programIds').sort({createdAt:-1}).lean();ok(res,items.map(toLegacyContest),'Concours de l’établissement');}));
router.get('/admin/concours/:contestId/candidats', authenticate, asyncHandler(async (req, res) => {
  const contest = await Contest.findOne(contestFilter(req.params.contestId)).populate('establishmentId').lean();
  if (!contest) throw new AppError(404, 'CONTEST_NOT_FOUND', 'Concours introuvable');
  if (req.admin.role !== 'super_admin' && !req.admin.establishmentIds.some(assigned => String(assigned) === String(contest.establishmentId?._id))) throw new AppError(403, 'ESTABLISHMENT_FORBIDDEN', 'Concours non attribué');
  const applications = await Application.find({ contestId: contest._id }).populate('candidateId programId').sort({ createdAt: -1 }).lean();
  const applicationIds = applications.map(application => application._id);
  const [documents, payments] = await Promise.all([
    ApplicationDocument.find({ applicationId: { $in: applicationIds } }).lean(),
    Payment.find({ applicationId: { $in: applicationIds } }).sort({ createdAt: -1 }).lean()
  ]);
  ok(res, applications.map(application => {
    const candidate = application.candidateId;
    const payment = payments.find(item => String(item.applicationId) === String(application._id));
    return {
      id: String(application._id), candidat_id: String(candidate?._id || ''), concours_id: contest.legacyId || String(contest._id), filiere_id: application.programId?.legacyId || String(application.programId?._id || ''),
      statut: application.status === 'approved' ? 'valide' : application.status === 'rejected' ? 'rejete' : 'en_attente', created_at: application.createdAt, updated_at: application.updatedAt,
      nupcan: application.nupcan, nomcan: candidate?.lastName || '', prncan: candidate?.firstName || '', maican: candidate?.email || '', telcan: candidate?.phone || '', dtncan: candidate?.birthDate, ldncan: candidate?.birthPlace || '', phtcan: candidate?.photoData || '',
      libcnc: contest.title, sescnc: '', fracnc: contest.fee || 0, nomfil: application.programId?.name || '',
      paiement: payment ? { statut: payment.status, montant: payment.amount, methode: payment.provider, reference_paiement: payment.paymentReference } : undefined,
      documents: documents.filter(document => String(document.applicationId) === String(application._id)).map(document => ({ id: String(document._id), type: document.type, statut: document.status }))
    };
  }), 'Candidatures du concours chargées');
}));
const subAdminView = admin => ({ ...adminView(admin), role: 'sub_admin', admin_role: admin.subAdminRole, permissions: admin.permissions || [], created_by: admin.createdBy });
const requireSubAdminManager = (req, _res, next) => {
  if (req.admin?.role === 'super_admin' || ['admin_etablissement', 'reviewer', 'admin'].includes(req.admin?.role)) return next();
  next(new AppError(403, 'SUBADMIN_MANAGEMENT_FORBIDDEN', 'Seul un administrateur d’établissement peut gérer les sous-administrateurs'));
};
router.get('/subadmins', authenticate, requireSubAdminManager, asyncHandler(async (req, res) => {
  const establishmentId = req.admin.role === 'super_admin' ? req.query.etablissement_id : req.admin.establishmentIds?.[0];
  const filter = { role: 'sub_admin', active: true };
  if (establishmentId) filter.establishmentIds = establishmentId;
  ok(res, (await Administrator.find(filter).populate('establishmentIds').sort({ createdAt: -1 }).lean()).map(subAdminView), 'Sous-administrateurs chargés');
}));
router.post('/subadmins', authenticate, requireSubAdminManager, asyncHandler(async (req, res) => {
  const role = String(req.body.admin_role || req.body.subAdminRole || '');
  if (!creatableSubAdminRoles.has(role)) throw new AppError(422, 'INVALID_SUBADMIN_ROLE', 'Le rôle doit être « gestion des notes » ou « gestion des documents »');
  const establishmentId = req.admin.role === 'super_admin' ? req.body.etablissement_id : req.admin.establishmentIds?.[0];
  if (!establishmentId) throw new AppError(422, 'ESTABLISHMENT_REQUIRED', 'Établissement obligatoire');
  const establishment = await Establishment.findOne(idFilter(establishmentId)).select('_id').lean();
  if (!establishment) throw new AppError(422, 'INVALID_ESTABLISHMENT', 'Établissement introuvable');
  const activeSubAdmins = await Administrator.countDocuments({ role: 'sub_admin', active: true, establishmentIds: establishment._id });
  if (activeSubAdmins >= 3) throw new AppError(409, 'SUBADMIN_LIMIT_REACHED', 'La limite de trois sous-administrateurs actifs est atteinte');
  const temporaryPassword = String(req.body.password || crypto.randomBytes(12).toString('base64url'));
  const admin = await Administrator.create({ firstName: String(req.body.prenom || '').trim(), lastName: String(req.body.nom || '').trim(), email: String(req.body.email || '').trim().toLowerCase(), passwordHash: await bcrypt.hash(temporaryPassword, 12), mustChangePassword: true, role: 'sub_admin', subAdminRole: role, permissions: rolePermissions[role], establishmentIds: [establishment._id], createdBy: req.admin._id, active: true });
  const populated = await Administrator.findById(admin._id).populate('establishmentIds').lean();
  let emailSent = false;
  try { await emailService.sendAdminCredentials({ email: populated.email, prenom: populated.firstName, nom: populated.lastName, temp_password: temporaryPassword, etablissement_nom: populated.establishmentIds?.[0]?.name }); emailSent = true; } catch (error) { console.error(JSON.stringify({ level: 'error', code: 'SUBADMIN_CREDENTIALS_EMAIL_FAILED', message: error.message })); }
  ok(res, { ...subAdminView(populated), delivery: { emailSent, ...(!emailSent && { temporaryPassword }) } }, emailSent ? 'Sous-administrateur créé et identifiants envoyés' : "Sous-administrateur créé, mais l'email n'a pas pu être envoyé", 201);
}));
router.delete('/subadmins/:id', authenticate, requireSubAdminManager, asyncHandler(async (req, res) => {
  const filter = { ...idFilter(req.params.id), role: 'sub_admin' };
  if (req.admin.role !== 'super_admin') filter.establishmentIds = req.admin.establishmentIds?.[0];
  const admin = await Administrator.findOneAndUpdate(filter, { $set: { active: false } }, { new: true }).lean();
  if (!admin) throw new AppError(404, 'SUBADMIN_NOT_FOUND', 'Sous-administrateur introuvable');
  ok(res, { id: String(admin._id) }, 'Sous-administrateur désactivé');
}));
router.get('/messages/admin',authenticate,requirePermission('manage_messages'),asyncHandler(async(req,res)=>{const query={};const ids=await scopedApplicationIds(req.admin);if(ids)query.applicationId={$in:ids};if(req.query.nupcan)query.legacyNupcan=String(req.query.nupcan);const items=await Message.find(query).populate('candidateId administratorId applicationId').sort({createdAt:-1}).limit(200).lean();ok(res,items.map(m=>({id:String(m._id),legacyId:m.legacyId,candidat_nupcan:m.applicationId?.nupcan||m.legacyNupcan||'',admin_id:m.administratorId?.legacyId,sujet:m.subject||'',message:m.body,expediteur:m.senderType==='administrator'?'admin':'candidat',statut:m.readAt?'lu':'non_lu',created_at:m.createdAt,updated_at:m.updatedAt,nomcan:m.candidateId?.lastName||'',prncan:m.candidateId?.firstName||'',maican:m.candidateId?.email||'',admin_nom:m.administratorId?.lastName||'',admin_prenom:m.administratorId?.firstName||''})),'Messages chargés');}));
router.post('/messages/admin',authenticate,requirePermission('manage_messages'),required('nupcan','message'),asyncHandler(async(req,res)=>{const application=await scopedApplication(req.admin,req.body.nupcan);const body=String(req.body.message).trim();if(!body)throw new AppError(422,'MESSAGE_REQUIRED','Le message est obligatoire');const item=await Message.create({applicationId:application._id,candidateId:application.candidateId._id,administratorId:req.admin._id,legacyNupcan:application.nupcan,subject:String(req.body.sujet||'Réponse de l’administration').trim(),body,senderType:'administrator'});await Notification.create({candidateId:application.candidateId._id,applicationId:application._id,legacyNupcan:application.nupcan,title:'Nouveau message de l’administration',body:item.body,channel:'in_app'});ok(res,messageView(await item.populate('administratorId')),'Message envoyé',201);}));
router.put('/messages/:id/marquer-lu',authenticate,requirePermission('manage_messages'),asyncHandler(async(req,res)=>{const item=await Message.findById(req.params.id).populate('applicationId');if(!item)throw new AppError(404,'MESSAGE_NOT_FOUND','Message introuvable');await scopedApplication(req.admin,item.applicationId._id);item.readAt=new Date();await item.save();ok(res,messageView(item),'Message marqué comme lu');}));
const adminView=a=>({id:String(a._id),legacyId:a.legacyId,nom:a.lastName,prenom:a.firstName,email:a.email,role:a.role,admin_role:a.subAdminRole||(a.role==='finance'?'paiements':'documents'),subAdminRole:a.subAdminRole,permissions:effectivePermissions(a),etablissement_id:a.establishmentIds?.[0]?.legacyId||a.establishmentIds?.[0]?._id,etablissement_object_id:a.establishmentIds?.[0]?._id,etablissement_nom:a.establishmentIds?.[0]?.name||'',statut:a.active?'actif':'inactif',active:a.active,derniere_connexion:a.lastLoginAt,created_at:a.createdAt});
router.get('/admin/management/admins',authenticate,requireSuperAdmin,asyncHandler(async(_req,res)=>ok(res,(await Administrator.find().populate('establishmentIds').sort({createdAt:-1}).lean()).map(adminView),'Administrateurs chargés')));
router.post('/admin/management/admins',authenticate,requireSuperAdmin,required('email'),asyncHandler(async(req,res)=>{
  if(await Administrator.exists({email:String(req.body.email).trim().toLowerCase()}))throw new AppError(409,'ADMIN_EMAIL_EXISTS','Un administrateur utilise déjà cette adresse email');
  const establishmentId=req.body.etablissement_id?await Establishment.findOne(establishmentFilter(req.body.etablissement_id)).select('_id').lean():null;
  if(req.body.etablissement_id&&!establishmentId)throw new AppError(422,'INVALID_ESTABLISHMENT','Établissement introuvable');
  const role=['super_admin','admin','reviewer','finance'].includes(req.body.role)?req.body.role:(req.body.admin_role==='paiements'?'finance':'reviewer');
  const temporaryPassword=String(req.body.password||crypto.randomBytes(12).toString('base64url'));
  const admin=await Administrator.create({firstName:req.body.prenom||req.body.firstName||'',lastName:req.body.nom||req.body.lastName||'',email:String(req.body.email).trim().toLowerCase(),passwordHash:await bcrypt.hash(temporaryPassword,12),mustChangePassword:true,role,establishmentIds:establishmentId?[establishmentId._id]:[],active:true});
  const populated=await Administrator.findById(admin._id).populate('establishmentIds').lean();
  let emailSent=false;
  try{
    await emailService.sendAdminCredentials({email:populated.email,prenom:populated.firstName,nom:populated.lastName,temp_password:temporaryPassword,etablissement_nom:populated.establishmentIds?.[0]?.name});
    emailSent=true;
  }catch(error){
    console.error(JSON.stringify({level:'error',code:'ADMIN_CREDENTIALS_EMAIL_FAILED',administratorId:String(admin._id),message:error.message}));
  }
  ok(res,{...adminView(populated),delivery:{emailSent,...(!emailSent&&{temporaryPassword})}},emailSent?'Administrateur créé et identifiants envoyés par email':"Administrateur créé, mais l'email n'a pas pu être envoyé",201);
}));
router.put('/admin/management/admins/:id',authenticate,requireSuperAdmin,asyncHandler(async(req,res)=>{const update={};if(req.body.nom!=null)update.lastName=req.body.nom;if(req.body.prenom!=null)update.firstName=req.body.prenom;if(req.body.email!=null)update.email=String(req.body.email).toLowerCase();if(req.body.role!=null&&['super_admin','admin','reviewer','finance'].includes(req.body.role))update.role=req.body.role;if(req.body.statut!=null)update.active=req.body.statut!=='inactif';if(req.body.password)update.passwordHash=await bcrypt.hash(String(req.body.password),12);if(req.body.etablissement_id){const e=await Establishment.findOne(establishmentFilter(req.body.etablissement_id));if(!e)throw new AppError(422,'INVALID_ESTABLISHMENT','Établissement introuvable');update.establishmentIds=[e._id];}const admin=await Administrator.findByIdAndUpdate(req.params.id,{$set:update},{new:true,runValidators:true}).populate('establishmentIds').lean();if(!admin)throw new AppError(404,'ADMIN_NOT_FOUND','Administrateur introuvable');ok(res,adminView(admin),'Administrateur modifié');}));
const resetAdministratorPassword=async id=>{const temporaryPassword=crypto.randomBytes(12).toString('base64url');const admin=await Administrator.findOneAndUpdate(idFilter(id),{$set:{passwordHash:await bcrypt.hash(temporaryPassword,12),mustChangePassword:true,active:true}},{new:true,runValidators:true}).populate('establishmentIds').lean();if(!admin)throw new AppError(404,'ADMIN_NOT_FOUND','Administrateur introuvable');return{admin,temporaryPassword};};
router.post('/admin/management/admins/:id/regenerate-password',authenticate,requireSuperAdmin,asyncHandler(async(req,res)=>{const {admin,temporaryPassword}=await resetAdministratorPassword(req.params.id);ok(res,{admin:adminView(admin),temporaryPassword},'Nouveau mot de passe temporaire généré');}));
router.post('/admin/management/admins/:id/resend-credentials',authenticate,requireSuperAdmin,asyncHandler(async(req,res)=>{const {admin,temporaryPassword}=await resetAdministratorPassword(req.params.id);let emailSent=false;try{await emailService.sendAdminCredentials({email:admin.email,prenom:admin.firstName,nom:admin.lastName,temp_password:temporaryPassword,etablissement_nom:admin.establishmentIds?.[0]?.name});emailSent=true;}catch(error){console.error(JSON.stringify({level:'error',code:'ADMIN_CREDENTIALS_RESEND_FAILED',administratorId:String(admin._id),message:error.message}));}ok(res,{admin:adminView(admin),delivery:{emailSent,...(!emailSent&&{temporaryPassword})}},emailSent?'Identifiants régénérés et envoyés par email':"Mot de passe régénéré, mais l'email n'a pas pu être envoyé");}));
router.delete('/admin/management/admins/:id',authenticate,requireSuperAdmin,asyncHandler(async(req,res)=>{if(req.admin._id.equals(req.params.id))throw new AppError(409,'SELF_DELETE_FORBIDDEN','Vous ne pouvez pas supprimer votre propre compte');const admin=await Administrator.findByIdAndUpdate(req.params.id,{$set:{active:false}},{new:true});if(!admin)throw new AppError(404,'ADMIN_NOT_FOUND','Administrateur introuvable');ok(res,{id:String(admin._id)},'Administrateur désactivé');}));
router.get('/support',authenticate,asyncHandler(async(req,res)=>{const page=Math.max(1,Number(req.query.page)||1),limit=Math.min(100,Math.max(1,Number(req.query.limit)||20));const query={};if(req.query.status&&req.query.status!=='all')query.status=req.query.status;if(req.query.search){const q=String(req.query.search).slice(0,100);query.$or=[{subject:{$regex:q,$options:'i'}},{body:{$regex:q,$options:'i'}}];}const [items,total]=await Promise.all([SupportRequest.find(query).populate('candidateId applicationId').sort({createdAt:-1}).skip((page-1)*limit).limit(limit).lean(),SupportRequest.countDocuments(query)]);ok(res,{requests:items.map(s=>({id:String(s._id),legacyId:s.legacyId,name:s.candidateId?`${s.candidateId.firstName} ${s.candidateId.lastName}`.trim():'',email:s.candidateId?.email||'',subject:s.subject,message:s.body,status:s.status,createdAt:s.createdAt,updatedAt:s.updatedAt,nupcan:s.applicationId?.nupcan||''})),page,total,totalPages:Math.max(1,Math.ceil(total/limit))},'Demandes de support chargées');}));
router.get('/candidats',authenticate,requirePermission('view_applications'),asyncHandler(async(req,res)=>{const scopedIds=await scopedApplicationIds(req.admin);const applicationQuery=scopedIds?{_id:{$in:scopedIds}}:{};const applications=await Application.find(applicationQuery).populate('contestId programId').lean();const candidateIds=[...new Set(applications.map(a=>String(a.candidateId)))];const appIds=applications.map(a=>a._id);const [candidates,documents,payments]=await Promise.all([Candidate.find({_id:{$in:candidateIds}}).populate('originProvinceId currentProvinceId assignedProvinceId').sort({createdAt:-1}).lean(),ApplicationDocument.find({applicationId:{$in:appIds}}).lean(),Payment.find({applicationId:{$in:appIds}}).sort({createdAt:-1}).lean()]);const result=candidates.map(c=>{const apps=applications.filter(a=>String(a.candidateId)===String(c._id));const ownIds=new Set(apps.map(a=>String(a._id))),docs=documents.filter(d=>ownIds.has(String(d.applicationId))),pays=payments.filter(p=>ownIds.has(String(p.applicationId))),latest=apps.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))[0];return{id:String(c._id),legacyId:c.legacyId,nupcan:latest?.nupcan||'',nipcan:c.nipcan||'',nomcan:c.lastName,prncan:c.firstName,maican:c.email||'',telcan:c.phone,dtncan:c.birthDate,province_origine:c.originProvinceId?.name||'',province_actuelle:c.currentProvinceId?.name||'',province_affectation:c.assignedProvinceId?.name||'',participations:apps.map(a=>({id:String(a._id),nupcan:a.nupcan,statut:a.status,concours:a.contestId?.title||'',filiere:a.programId?.name||''})),documents:docs.map(d=>({id:String(d._id),type:d.type,statut:d.status})),paiements:pays.map(p=>({id:String(p._id),montant:p.amount,statut:p.status,reference:p.paymentReference})),paiement:pays[0]?{statut:{paid:'valide',pending:'en_attente',processing:'en_attente',failed:'rejete',cancelled:'rejete'}[pays[0].status]||pays[0].status,montant:pays[0].amount}:null,created_at:c.createdAt,updated_at:c.updatedAt};});ok(res,result,'Candidats et informations liées chargés');}));
router.post('/candidats', authenticationLimiter, candidatePhotoUpload.single('phtcan'), validateUploadedFiles, required('nomcan','prncan','telcan','concours_id','filiere_id'), asyncHandler(async(req,res)=>{
  const [contest,program,originProvince,currentProvince,assignedProvince]=await Promise.all([
    Contest.findOne(contestFilter(req.body.concours_id)).lean(),
    Program.findOne(idFilter(req.body.filiere_id)).lean(),
    req.body.proorg?Province.findOne(idFilter(req.body.proorg)).lean():null,
    req.body.proact?Province.findOne(idFilter(req.body.proact)).lean():null,
    req.body.proaff?Province.findOne(idFilter(req.body.proaff)).lean():null
  ]);
  if(!contest||!program)throw new AppError(422,'INVALID_SELECTION','Concours ou filière introuvable');
  if(contest.programIds?.length&&!contest.programIds.some(id=>String(id)===String(program._id)))throw new AppError(422,'PROGRAM_NOT_AVAILABLE','Cette filière ne fait pas partie du concours');
  const photoData=req.file?`data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`:undefined;
  const existingCandidate=req.candidate;
  if(req.body.nipcan && (!existingCandidate || String(req.body.nipcan).trim().toUpperCase() !== existingCandidate.nipcan)) throw new AppError(403,'CANDIDATE_FORBIDDEN','Ce NIPCAN ne correspond pas à votre compte');
  if(existingCandidate && req.body.maican && String(req.body.maican).trim().toLowerCase() !== existingCandidate.email) throw new AppError(422,'ACCOUNT_EMAIL_MISMATCH','Utilisez l’adresse email vérifiée de votre compte');
  if(req.body.nipcan&&!existingCandidate)throw new AppError(404,'CANDIDATE_NOT_FOUND','Aucun candidat ne correspond à ce NIPCAN');
  if(existingCandidate){
    const duplicateApplication=await Application.findOne({candidateId:existingCandidate._id,contestId:contest._id}).select('nupcan').lean();
    if(duplicateApplication)throw new AppError(409,'APPLICATION_ALREADY_EXISTS',`Vous êtes déjà inscrit à ce concours (${duplicateApplication.nupcan})`);
    const requestedEmail=req.body.maican?String(req.body.maican).trim().toLowerCase():existingCandidate.email;
    if(requestedEmail&&await Candidate.exists({_id:{$ne:existingCandidate._id},email:requestedEmail}))throw new AppError(409,'CANDIDATE_EMAIL_ALREADY_EXISTS','Cette adresse e-mail appartient déjà à un autre candidat');
    Object.assign(existingCandidate,{firstName:String(req.body.prncan).trim(),lastName:String(req.body.nomcan).trim(),email:req.body.maican?String(req.body.maican).trim().toLowerCase():existingCandidate.email,phone:String(req.body.telcan).trim(),birthDate:req.body.dtncan?new Date(req.body.dtncan):existingCandidate.birthDate,birthPlace:req.body.ldncan?String(req.body.ldncan).trim():existingCandidate.birthPlace,photoData:photoData||existingCandidate.photoData,originProvinceId:originProvince?._id||existingCandidate.originProvinceId,currentProvinceId:currentProvince?._id||existingCandidate.currentProvinceId,assignedProvinceId:assignedProvince?._id||existingCandidate.assignedProvinceId});
    await existingCandidate.save();
  }
  const application=await createApplication({
    contestId:contest._id,
    programId:program._id,
    candidateId:existingCandidate?._id,
    candidate:{
      nipcan:req.body.nipcan?String(req.body.nipcan).trim().toUpperCase():undefined,
      firstName:String(req.body.prncan).trim(),
      lastName:String(req.body.nomcan).trim(),
      email:req.body.maican?String(req.body.maican).trim().toLowerCase():undefined,
      phone:String(req.body.telcan).trim(),
      birthDate:req.body.dtncan?new Date(req.body.dtncan):undefined,
      birthPlace:req.body.ldncan?String(req.body.ldncan).trim():undefined,
      photoData,
      originProvinceId:originProvince?._id,
      currentProvinceId:currentProvince?._id,
      assignedProvinceId:assignedProvince?._id
    }
  });
  const candidate=existingCandidate||await Candidate.findById(application.candidateId).lean();
  const accountCredentials = application.$locals.accountCredentials;
  const accountSession = accountCredentials ? await createCandidateSession(candidate) : null;
  res.set('Cache-Control', 'no-store');
  let emailSent=false;
  if (candidate.email) {
    try {
      await emailService.sendRegistrationConfirmation({
        nipcan: candidate.nipcan,
        nupcan: application.nupcan,
        nomcan: candidate.lastName,
        prncan: candidate.firstName,
        maican: candidate.email,
        accountCredentials
      }, { libcnc: contest.title, documents_requis: [] });
      emailSent=true;
    } catch (error) {
      console.error(JSON.stringify({level:'error',code:'CANDIDATE_CREDENTIALS_EMAIL_FAILED',candidateId:String(candidate._id),message:error.message}));
    }
  }
  ok(res,{id:String(application.candidateId),nupcan:application.nupcan,nipcan:candidate.nipcan,concours_id:contest.legacyId||String(contest._id),filiere_id:program.legacyId||String(program._id),nomcan:req.body.nomcan,prncan:req.body.prncan,maican:req.body.maican||'',dtncan:req.body.dtncan||'',telcan:req.body.telcan,ldncan:req.body.ldncan||'',phtcan:candidate.photoData||null,niveau_id:req.body.niveau_id||null,proorg:originProvince?.legacyId||req.body.proorg||null,proact:currentProvince?.legacyId||req.body.proact||null,proaff:assignedProvince?.legacyId||req.body.proaff||null,created_at:application.createdAt,updated_at:application.updatedAt,delivery:{emailSent},...(accountCredentials ? {account: {...accountCredentials, ...accountSession}} : {})},emailSent?'Candidature créée et identifiants envoyés par email':"Candidature créée, mais l'email n'a pas pu être envoyé",201);
}));
router.post('/candidats/nipcan/verify', authenticateCandidate, required('nipcan'), asyncHandler(async (req, res) => {
  const nipcan = String(req.body.nipcan).trim().toUpperCase();
  if (nipcan !== req.candidate.nipcan) throw new AppError(403, 'CANDIDATE_FORBIDDEN', 'Ce NIPCAN ne correspond pas à votre compte');
  const candidate = await Candidate.findOne({ nipcan }).lean();
  if (!candidate) throw new AppError(404, 'CANDIDATE_NOT_FOUND', 'NIPCAN invalide. Aucun candidat trouvé avec cet identifiant.');
  ok(res, { id: String(candidate._id), nipcan: candidate.nipcan, nom: candidate.lastName, prenom: candidate.firstName, maican: candidate.email || '' }, 'NIPCAN valide');
}));
const legacyDocumentStatus = status => ({ approved: 'valide', rejected: 'rejete', under_review: 'en_attente', uploaded: 'en_attente', pending: 'en_attente' }[status] || status);
const legacyPaymentStatus = status => ({ paid: 'valide', pending: 'en_attente', processing: 'en_attente', failed: 'rejete', cancelled: 'rejete', refunded: 'rembourse' }[status] || status);
const legacyApplicationStatus = status => ({ approved:'valide', rejected:'rejete', cancelled:'annule', draft:'brouillon', submitted:'en_attente', under_review:'en_cours' }[status] || status);
router.get('/candidats/nipcan/:nipcan/dashboard', asyncHandler(async (req, res) => {
  const nipcan = String(req.params.nipcan).trim().toUpperCase();
  const candidate = await Candidate.findOne({ nipcan }).lean();
  if (!candidate) throw new AppError(404, 'CANDIDATE_NOT_FOUND', 'Candidat introuvable avec ce NIPCAN');
  const applications = await Application.find({ candidateId: candidate._id }).populate('contestId').populate('programId').sort({ createdAt: -1 }).lean();
  const applicationIds = applications.map(application => application._id);
  const [documents, payments] = await Promise.all([
    ApplicationDocument.find({ applicationId: { $in: applicationIds } }).lean(),
    Payment.find({ applicationId: { $in: applicationIds } }).sort({ createdAt: -1 }).lean()
  ]);
  const requirements = await DocumentRequirement.find({ contestId: { $in: applications.map(application => application.contestId?._id).filter(Boolean) }, active: true, required: true }).select('contestId programId').lean();
  const candidatures = applications.map(application => {
    const applicationDocuments = documents.filter(document => String(document.applicationId) === String(application._id));
    const validDocuments = applicationDocuments.filter(document => document.status === 'approved').length;
    const requiredDocuments = requirements.filter(requirement => String(requirement.contestId) === String(application.contestId?._id) && (!requirement.programId || String(requirement.programId) === String(application.programId?._id)));
    const submittedDocuments = new Set(applicationDocuments.filter(document => document.requirementId).map(document => String(document.requirementId))).size;
    const payment = payments.find(item => String(item.applicationId) === String(application._id));
    const documentsComplete = submittedDocuments >= requiredDocuments.length;
    const paymentComplete = payment?.status === 'paid';
    const resultAvailable = ['approved', 'rejected'].includes(application.status);
    const completed = [true, documentsComplete, paymentComplete, resultAvailable].filter(Boolean).length;
    return {
      nupcan: application.nupcan,
      concours: { id: application.contestId?.legacyId || String(application.contestId?._id || ''), libcnc: application.contestId?.title || application.contestSnapshot?.title || '', etablissement: application.contestSnapshot?.establishmentName || '' },
      filiere: { id: application.programId?.legacyId || String(application.programId?._id || ''), nomfil: application.programId?.name || application.contestSnapshot?.programName || '' },
      statut: application.status,
      progression: completed * 25,
      created_at: application.createdAt,
      documents_count: applicationDocuments.length,
      documents_requis: requiredDocuments.length,
      documents_deposes: submittedDocuments,
      documents_valides: validDocuments,
      paiement_statut: payment ? legacyPaymentStatus(payment.status) : null,
      etapes: { inscription: true, documents: documentsComplete, paiement: paymentComplete, resultats: resultAvailable }
    };
  });
  ok(res, {
    candidat: { id: String(candidate._id), nipcan: candidate.nipcan, nomcan: candidate.lastName, prncan: candidate.firstName, maican: candidate.email || '', telcan: candidate.phone, phtcan: candidate.photoData || '' },
    candidatures,
    statistiques: { total: candidatures.length, en_cours: applications.filter(application => ['draft', 'submitted', 'under_review'].includes(application.status)).length, completes: applications.filter(application => application.status === 'approved').length }
  }, 'Dashboard candidat chargé');
}));
router.get('/candidats/nip/:nip',asyncHandler(async(req,res)=>{
  const c=await Candidate.findOne({nipcan:String(req.params.nip).trim().toUpperCase()}).populate('originProvinceId currentProvinceId assignedProvinceId').lean();
  if(!c)throw new AppError(404,'CANDIDATE_NOT_FOUND','Candidat introuvable avec ce NIPCAN');
  const application=await Application.findOne({candidateId:c._id}).sort({createdAt:-1}).populate('contestId').populate('programId').lean();
  ok(res,{id:String(c._id),nupcan:application?.nupcan||'',nipcan:c.nipcan,concours_id:application?.contestId?.legacyId||String(application?.contestId?._id||''),filiere_id:application?.programId?.legacyId||String(application?.programId?._id||''),nomcan:c.lastName,prncan:c.firstName,maican:c.email||'',telcan:c.phone,dtncan:c.birthDate,ldncan:c.birthPlace||'',phtcan:c.photoData||null,proorg:c.originProvinceId?.legacyId||c.originProvinceId?._id||c.originProvinceId,proact:c.currentProvinceId?.legacyId||c.currentProvinceId?._id||c.currentProvinceId,proaff:c.assignedProvinceId?.legacyId||c.assignedProvinceId?._id||c.assignedProvinceId,statut:application?.status||'',created_at:c.createdAt,updated_at:c.updatedAt},'Candidat chargé');
}));
// Lecture publique limitée aux données nécessaires au parcours candidat. Le NUPCAN
// est le secret de suivi; cette route ne retourne jamais les données administrateur.
router.get('/candidats/nupcan/:nupcan',asyncHandler(async(req,res)=>{const application=await Application.findOne({nupcan:String(req.params.nupcan).trim().toUpperCase()}).populate('candidateId').populate('contestId').populate('programId').lean();if(!application||!application.candidateId)throw new AppError(404,'CANDIDATE_NOT_FOUND','Candidat introuvable');const c=application.candidateId;ok(res,{id:String(c._id),nupcan:application.nupcan,nipcan:c.nipcan||'',concours_id:application.contestId?.legacyId||String(application.contestId?._id),filiere_id:application.programId?.legacyId||String(application.programId?._id),nomcan:c.lastName,prncan:c.firstName,maican:c.email||'',telcan:c.phone,dtncan:c.birthDate,ldncan:c.birthPlace||'',phtcan:c.photoData||null,proorg:c.originProvinceId?.legacyId||c.originProvinceId?._id||c.originProvinceId,proact:c.currentProvinceId?.legacyId||c.currentProvinceId?._id||c.currentProvinceId,proaff:c.assignedProvinceId?.legacyId||c.assignedProvinceId?._id||c.assignedProvinceId,statut:legacyApplicationStatus(application.status),created_at:c.createdAt,updated_at:c.updatedAt},'Candidat chargé');}));
router.get('/candidats/nupcan/:nupcan/nipcan', asyncHandler(async (req, res) => { const application = await Application.findOne({ nupcan: String(req.params.nupcan).toUpperCase() }).populate('candidateId').lean(); if (!application?.candidateId?.nipcan) throw new AppError(404, 'CANDIDATE_NOT_FOUND', 'NIPCAN introuvable pour cette candidature'); ok(res, { nipcan: application.candidateId.nipcan, nupcan: application.nupcan }, 'NIPCAN trouvé'); }));
const documentView = d => { const statut=legacyDocumentStatus(d.status); return { id: String(d._id), document_id: String(d._id), requirement_id: d.requirementId ? String(d.requirementId) : null, nomdoc: d.type, nom_fichier: d.originalName || d.safeName, chemin_fichier: d.storageKey, type: d.type, mime_type:d.mimeType, version:d.version||1, obligatoire: d.required, taille: d.size, statut, document_statut:statut, commentaire_validation: d.rejectionReason || '', ai_status: d.aiStatus || 'disabled', ai_recommendation: d.aiRecommendation || null, ai_confidence: d.aiConfidence ?? null, ai_reason: d.aiReason || '', created_at: d.createdAt, updated_at: d.updatedAt }; };
router.use('/documents/:id',asyncHandler(async(req,_res,next)=>{if(['GET','HEAD'].includes(req.method))return next();const document=await ApplicationDocument.findById(req.params.id).populate({path:'applicationId',populate:{path:'contestId'}});if(!document)throw new AppError(404,'DOCUMENT_NOT_FOUND','Document introuvable');assertContestWritable(document.applicationId?.contestId);next();}));
router.get('/dossiers/nupcan/:nupcan', asyncHandler(async(req,res)=>{const application=await Application.findOne({nupcan:String(req.params.nupcan).toUpperCase()}).lean();if(!application)throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const docs=await ApplicationDocument.find({applicationId:application._id}).sort({createdAt:-1}).lean();ok(res,docs.map(documentView),'Documents chargés');}));
router.get('/dossiers/admin/all', authenticate, requirePermission('view_documents'), asyncHandler(async (req, res) => {
  const ids=await scopedApplicationIds(req.admin);const query=ids?{applicationId:{$in:ids}}:{};
  const documents = await ApplicationDocument.find(query).populate({ path: 'applicationId', populate: [{ path: 'candidateId' }, { path: 'contestId' }] }).sort({ createdAt: -1 }).lean();
  ok(res, documents.map(document => ({ ...documentView(document), nupcan: document.applicationId?.nupcan || '', nomcan: document.applicationId?.candidateId?.lastName || '', prncan: document.applicationId?.candidateId?.firstName || '', maican: document.applicationId?.candidateId?.email || '', libcnc: document.applicationId?.contestId?.title || '' })), 'Dossiers administrateur chargés');
}));
router.get('/candidats/nupcan/:nupcan/documents', asyncHandler(async(req,res)=>{const application=await Application.findOne({nupcan:String(req.params.nupcan).trim().toUpperCase()}).lean();if(!application)throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');ok(res,(await ApplicationDocument.find({applicationId:application._id}).sort({createdAt:-1}).lean()).map(documentView),'Documents chargés');}));
router.get('/candidats/nupcan/:nupcan/document-checklist', asyncHandler(async(req,res)=>{const application=await Application.findOne({nupcan:String(req.params.nupcan).trim().toUpperCase()}).lean();if(!application)throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const [requirements,documents]=await Promise.all([DocumentRequirement.find({contestId:application.contestId,active:true,$or:[{programId:null},{programId:application.programId}]}).sort({required:-1,createdAt:1}).lean(),ApplicationDocument.find({applicationId:application._id}).sort({createdAt:-1}).lean()]);const byRequirement=new Map(documents.filter(document=>document.requirementId).map(document=>[String(document.requirementId),document]));const linkedDocumentIds=new Set([...byRequirement.values()].map(document=>String(document._id)));const checklist=requirements.map(requirement=>({requirement:requirementView(requirement),document:byRequirement.has(String(requirement._id))?documentView(byRequirement.get(String(requirement._id))):null}));const supplemental=documents.filter(document=>!linkedDocumentIds.has(String(document._id))).map(documentView);ok(res,{nupcan:application.nupcan,checklist,supplemental,summary:{required:requirements.filter(item=>item.required).length,submitted:checklist.filter(item=>item.document).length,approved:checklist.filter(item=>item.document?.statut==='valide').length,missing:checklist.filter(item=>item.requirement.required&&!item.document).length,rejected:checklist.filter(item=>item.document?.statut==='rejete').length}},'Checklist documentaire chargée');}));
router.post('/dossiers', documentUpload.array('documents', 15), validateUploadedFiles, asyncHandler(async (req, res) => {
  const nupcan = String(req.body?.nupcan || '').trim().toUpperCase();
  const application = await Application.findOne({ nupcan }).lean();
  if (!application) throw new AppError(404, 'APPLICATION_NOT_FOUND', 'Candidature introuvable');
  assertContestWritable(await Contest.findById(application.contestId).lean());
  if (!req.files?.length) throw new AppError(422, 'DOCUMENTS_REQUIRED', 'Au moins un document est requis');
  const documents = await ApplicationDocument.insertMany(req.files.map(file => ({
    applicationId: application._id,
    candidateId: application.candidateId,
    type: file.originalname,
    storageKey: `documents/${nupcan}/${crypto.randomUUID()}`,
    contentData: `data:${file.mimetype};base64,${file.buffer.toString('base64')}`,
    originalName: file.originalname,
    safeName: file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'),
    mimeType: file.mimetype,
    size: file.size,
    checksum: crypto.createHash('sha256').update(file.buffer).digest('hex'),
    status: 'uploaded'
  })));
  ok(res, documents.map(documentView), 'Documents chargés', 201);
}));
router.post('/documents', documentUpload.single('file'), asyncHandler(async(req,res)=>{const nupcan=String(req.body?.nupcan||'').trim().toUpperCase();const application=await Application.findOne({nupcan}).populate('contestId').lean();if(!application)throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');assertContestWritable(application.contestId);if(!req.file)throw new AppError(422,'DOCUMENT_REQUIRED','Un document est requis');let requirement=null;if(req.body.requirement_id){requirement=await DocumentRequirement.findOne({_id:req.body.requirement_id,contestId:application.contestId._id,active:true}).lean();if(!requirement)throw new AppError(422,'INVALID_DOCUMENT_REQUIREMENT','Ce document ne fait pas partie des pièces demandées pour ce concours');const exists=await ApplicationDocument.exists({applicationId:application._id,requirementId:requirement._id});if(exists)throw new AppError(409,'DOCUMENT_ALREADY_SUBMITTED','Cette pièce a déjà été téléversée. Utilisez le remplacement.');}const file=req.file;if(requirement?.acceptedMimeTypes?.length&&!requirement.acceptedMimeTypes.includes(file.mimetype))throw new AppError(422,'INVALID_DOCUMENT_TYPE','Format de fichier non autorisé pour cette pièce');if(requirement?.maxSizeBytes&&file.size>requirement.maxSizeBytes)throw new AppError(422,'DOCUMENT_TOO_LARGE','Le fichier dépasse la taille autorisée');const document=await ApplicationDocument.create({applicationId:application._id,candidateId:application.candidateId,requirementId:requirement?._id,type:requirement?.name||String(req.body.nomdoc||file.originalname),required:requirement?.required||false,storageKey:`documents/${nupcan}/${crypto.randomUUID()}`,contentData:`data:${file.mimetype};base64,${file.buffer.toString('base64')}`,originalName:file.originalname,safeName:file.originalname.replace(/[^a-zA-Z0-9._-]/g,'_'),mimeType:file.mimetype,size:file.size,checksum:crypto.createHash('sha256').update(file.buffer).digest('hex'),status:'uploaded'});ok(res,documentView(document),'Document ajouté',201);}));
router.put('/documents/:id/replace', documentUpload.single('file'), asyncHandler(async(req,res)=>{if(!req.file)throw new AppError(422,'DOCUMENT_REQUIRED','Un document est requis');const old=await ApplicationDocument.findById(req.params.id);if(!old)throw new AppError(404,'DOCUMENT_NOT_FOUND','Document introuvable');const file=req.file;old.type=String(req.body.nomdoc||old.type);old.contentData=`data:${file.mimetype};base64,${file.buffer.toString('base64')}`;old.originalName=file.originalname;old.safeName=file.originalname.replace(/[^a-zA-Z0-9._-]/g,'_');old.mimeType=file.mimetype;old.size=file.size;old.checksum=crypto.createHash('sha256').update(file.buffer).digest('hex');old.status='uploaded';old.rejectionReason=undefined;old.version+=1;await old.save();ok(res,documentView(old),'Document remplacé');}));
router.put('/document-validation/:id', authenticate, requirePermission('validate_documents'), asyncHandler(async (req, res) => {
  const status = { valide: 'approved', rejete: 'rejected', approved: 'approved', rejected: 'rejected' }[req.body.statut || req.body.status];
  if (!status) throw new AppError(422, 'INVALID_DOCUMENT_STATUS', 'Statut de document invalide');
  const existing = await ApplicationDocument.findById(req.params.id).populate({path:'applicationId',populate:{path:'contestId'}});
  if (!existing) throw new AppError(404, 'DOCUMENT_NOT_FOUND', 'Document introuvable');
  assertContestAccess(req.admin, existing.applicationId.contestId); assertContestWritable(existing.applicationId.contestId);
  const document = await ApplicationDocument.findByIdAndUpdate(req.params.id, { $set: { status, rejectionReason: status === 'rejected' ? String(req.body.commentaire || '').trim() : undefined } }, { new: true, runValidators: true }).lean();
  await Notification.create({candidateId:existing.applicationId.candidateId,applicationId:existing.applicationId._id,legacyNupcan:existing.applicationId.nupcan,title:status==='approved'?'Document validé':'Document rejeté',body:status==='approved'?`Votre document « ${existing.type||'document'} » a été validé.`:`Votre document « ${existing.type||'document'} » a été rejeté. ${String(req.body.commentaire||'').trim()}`,channel:'in_app'});
  ok(res, documentView(document), 'Statut du document mis à jour');
}));
router.post('/email/receipt', asyncHandler(async(req,res)=>{const data=req.body?.candidatData||{},candidate=data.candidat||data,concours=data.concours||{};const maican=String(req.body?.maican||candidate.maican||'').trim().toLowerCase(),nupcan=String(req.body?.nupcan||candidate.nupcan||'').trim().toUpperCase();if(!maican||!maican.includes('@'))throw new AppError(422,'EMAIL_REQUIRED','Adresse email invalide');if(!nupcan)throw new AppError(422,'NUPCAN_REQUIRED','NUPCAN manquant');await emailService.sendReceiptEmail({maican,nupcan,prncan:candidate.prncan||candidate.firstName||'',nomcan:candidate.nomcan||candidate.lastName||'',libcnc:concours.libcnc||concours.title||''},req.body?.pdfAttachment?{content:req.body.pdfAttachment,filename:`Recu_Candidature_${nupcan}.pdf`}:undefined);ok(res,{success:true},'Reçu envoyé par email');}));
router.post('/email/document-validation', asyncHandler(async(req,res)=>{const candidat=req.body?.candidat||{},document=req.body?.document||{},maican=String(candidat.maican||req.body?.to||'').trim().toLowerCase();if(!maican||!maican.includes('@'))throw new AppError(422,'EMAIL_REQUIRED','Adresse email invalide');if(!document.nomdoc&&!document.nom)throw new AppError(422,'DOCUMENT_REQUIRED','Document manquant');await emailService.sendDocumentValidationEmail({maican,documentName:document.nomdoc||document.nom,statut:req.body.statut,commentaire:req.body.commentaire});ok(res,{success:true},'Notification envoyée par email');}));
router.patch('/documents/:id', required('nomdoc'), asyncHandler(async(req,res)=>{const item=await ApplicationDocument.findById(req.params.id);if(!item)throw new AppError(404,'DOCUMENT_NOT_FOUND','Document introuvable');if(item.requirementId)throw new AppError(409,'REQUIRED_DOCUMENT_LOCKED','Le libellé d’une pièce exigée est défini par le concours');item.type=String(req.body.nomdoc).trim();if(!item.type)throw new AppError(422,'VALIDATION_ERROR','Le nom du document est obligatoire');await item.save();ok(res,documentView(item),'Document modifié');}));
router.delete('/documents/:id', asyncHandler(async(req,res)=>{const item=await ApplicationDocument.findByIdAndDelete(req.params.id);if(!item)throw new AppError(404,'DOCUMENT_NOT_FOUND','Document introuvable');ok(res,{id:String(item._id)},'Document supprimé');}));
router.get('/documents/:id/download', asyncHandler(async(req,res)=>{const item=await ApplicationDocument.findById(req.params.id).lean();if(!item?.contentData)throw new AppError(404,'DOCUMENT_NOT_FOUND','Fichier introuvable');const match=/^data:([^;]+);base64,(.*)$/.exec(item.contentData);if(!match)throw new AppError(500,'INVALID_DOCUMENT_DATA','Fichier illisible');res.type(match[1]).set({'Content-Disposition':`inline; filename="${String(item.safeName||item.originalName||'document').replace(/["\r\n]/g,'_')}"`,'Cross-Origin-Resource-Policy':'cross-origin'}).send(Buffer.from(match[2],'base64'));}));
const applicationByNupcan = nupcan => Application.findOne({ nupcan: String(nupcan).trim().toUpperCase() }).lean();
const notificationView = item => ({ id: String(item._id), titre: item.title || 'Notification', message: item.body || '', type: item.channel || 'information', statut: item.readAt ? 'lu' : 'non_lu', created_at: item.createdAt });
router.get('/notifications/unread',authenticate,asyncHandler(async(req,res)=>{const items=await Notification.find({recipientAdministratorId:req.admin._id,readAt:null}).sort({createdAt:-1}).limit(50).lean();ok(res,items.map(item=>({...notificationView(item),link:'/admin/dossiers'})),'Notifications administrateur chargées');}));
router.get('/notifications/candidat/:nupcan', authenticateCandidate, asyncHandler(async(req,res)=>{const application=await applicationByNupcan(req.params.nupcan);if(!application||String(application.candidateId)!==String(req.candidate._id))throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const items=await Notification.find({recipientAdministratorId:{$exists:false},$or:[{applicationId:application._id},{candidateId:application.candidateId},{legacyNupcan:application.nupcan}]}).sort({createdAt:-1}).lean();ok(res,items.map(notificationView),'Notifications chargées');}));
router.put('/notifications/:id/read', authenticateCandidate, asyncHandler(async(req,res)=>{const item=await Notification.findOneAndUpdate({_id:req.params.id,candidateId:req.candidate._id,recipientAdministratorId:{$exists:false}},{$set:{readAt:new Date()}},{new:true}).lean();if(!item)throw new AppError(404,'NOTIFICATION_NOT_FOUND','Notification introuvable');ok(res,notificationView(item),'Notification lue');}));
router.delete('/notifications/:id', authenticateCandidate, asyncHandler(async(req,res)=>{const item=await Notification.findOneAndDelete({_id:req.params.id,candidateId:req.candidate._id,recipientAdministratorId:{$exists:false}});if(!item)throw new AppError(404,'NOTIFICATION_NOT_FOUND','Notification introuvable');ok(res,{id:String(item._id)},'Notification supprimée');}));
router.delete('/notifications/candidat/:nupcan', authenticateCandidate, asyncHandler(async(req,res)=>{const application=await applicationByNupcan(req.params.nupcan);if(!application||String(application.candidateId)!==String(req.candidate._id))throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const result=await Notification.deleteMany({candidateId:req.candidate._id,recipientAdministratorId:{$exists:false},$or:[{applicationId:application._id},{legacyNupcan:application.nupcan}]});ok(res,{deletedCount:result.deletedCount},'Notifications supprimées');}));
const messageView = item => ({id:String(item._id),sujet:item.subject||'',message:item.body,expediteur:item.senderType==='administrator'?'admin':'candidat',statut:item.readAt?'lu':'non_lu',created_at:item.createdAt,admin_nom:item.administratorId?.lastName||'',admin_prenom:item.administratorId?.firstName||''});
router.get('/messages/candidat/:nupcan', authenticateCandidate, asyncHandler(async(req,res)=>{const application=await applicationByNupcan(req.params.nupcan);if(!application||String(application.candidateId)!==String(req.candidate._id))throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const items=await Message.find({$or:[{applicationId:application._id},{legacyNupcan:application.nupcan}]}).populate('administratorId').sort({createdAt:1}).lean();ok(res,items.map(messageView),'Messages chargés');}));
router.post('/messages/candidat', authenticateCandidate, required('nupcan','message'), asyncHandler(async(req,res)=>{const application=await applicationByNupcan(req.body.nupcan);if(!application||String(application.candidateId)!==String(req.candidate._id))throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const body=String(req.body.message).trim();if(!body)throw new AppError(422,'MESSAGE_REQUIRED','Le message est obligatoire');const item=await Message.create({applicationId:application._id,candidateId:application.candidateId,legacyNupcan:application.nupcan,subject:String(req.body.sujet||'Sans objet').trim(),body,senderType:'candidate'});ok(res,messageView(item),'Message envoyé',201);}));
router.put('/notifications/candidat/:nupcan/read-all', authenticateCandidate, asyncHandler(async(req,res)=>{const application=await applicationByNupcan(req.params.nupcan);if(!application||String(application.candidateId)!==String(req.candidate._id))throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const result=await Notification.updateMany({candidateId:req.candidate._id,recipientAdministratorId:{$exists:false},$or:[{applicationId:application._id},{legacyNupcan:application.nupcan}],readAt:null},{$set:{readAt:new Date()}});ok(res,{modifiedCount:result.modifiedCount},'Notifications marquées comme lues');}));
router.get('/grades/candidat/:nupcan', asyncHandler(async(req,res)=>{const application=await applicationByNupcan(req.params.nupcan);if(!application)throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const grades=await Grade.find({applicationId:application._id}).populate('subjectId').lean();const notes=grades.map(grade=>({id:String(grade._id),note:grade.score,nommat:grade.subjectId?.name||'',coefmat:grade.coefficient||1}));const coefficientTotal=notes.reduce((sum,note)=>sum+note.coefmat,0);const moyenneGenerale=coefficientTotal?Number((notes.reduce((sum,note)=>sum+note.note*note.coefmat,0)/coefficientTotal).toFixed(2)):null;ok(res,{notes,moyenneGenerale},'Notes chargées');}));
router.get('/matieres', authenticate, requirePermission('enter_grades'), asyncHandler(async(_req,res)=>ok(res,(await Subject.find().sort({name:1}).lean()).map(subject=>({id:subject.legacyId||String(subject._id),_id:String(subject._id),nom_matiere:subject.name,coefficient:subject.coefficient||1})),'Matières chargées')));
router.get('/notes/candidat/:candidateId/concours/:contestId', authenticate, requirePermission('enter_grades'), asyncHandler(async(req,res)=>{const [candidate,contest]=await Promise.all([Candidate.findOne(idFilter(req.params.candidateId)).lean(),Contest.findOne(idFilter(req.params.contestId)).lean()]);if(!candidate||!contest)throw new AppError(404,'SELECTION_NOT_FOUND','Candidat ou concours introuvable');const application=await Application.findOne({candidateId:candidate._id,contestId:contest._id}).lean();if(!application)throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const grades=await Grade.find({applicationId:application._id}).populate('subjectId').lean();const notes=grades.map(grade=>({id:String(grade._id),matiere_id:grade.subjectId?.legacyId||String(grade.subjectId?._id),nom_matiere:grade.subjectId?.name||'',note:grade.score,coefficient:grade.coefficient||1}));const total=notes.reduce((sum,note)=>sum+note.coefficient,0);ok(res,{notes,moyenne:total?(notes.reduce((sum,note)=>sum+note.note*note.coefficient,0)/total).toFixed(2):null},'Notes chargées');}));
router.post('/notes', authenticate, requirePermission('enter_grades'), required('candidat_id','concours_id','matiere_id','note'), asyncHandler(async(req,res)=>{const [candidate,contest,subject]=await Promise.all([Candidate.findOne(idFilter(req.body.candidat_id)).lean(),Contest.findOne(idFilter(req.body.concours_id)).lean(),Subject.findOne(idFilter(req.body.matiere_id)).lean()]);if(!candidate||!contest||!subject)throw new AppError(422,'INVALID_GRADE_SELECTION','Candidat, concours ou matière invalide');assertContestAccess(req.admin,contest);assertContestWritable(contest);const application=await Application.findOne({candidateId:candidate._id,contestId:contest._id}).lean();if(!application)throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const score=Number(req.body.note);if(!Number.isFinite(score)||score<0||score>20)throw new AppError(422,'INVALID_GRADE','La note doit être comprise entre 0 et 20');const grade=await Grade.findOneAndUpdate({applicationId:application._id,subjectId:subject._id},{$set:{score,maximumScore:20,coefficient:Number(req.body.coefficient||subject.coefficient||1),enteredBy:req.admin._id}},{upsert:true,new:true,runValidators:true});await Notification.create({candidateId:candidate._id,applicationId:application._id,legacyNupcan:application.nupcan,title:'Nouvelle note disponible',body:`Votre note de ${subject.name} est disponible dans votre espace candidat.`,channel:'in_app'});if(candidate.email)emailService.sendEmail?.(candidate.email,'Vos résultats GabConcours',`<p>Votre note de <strong>${subject.name}</strong> est maintenant disponible dans votre espace candidat.</p>`).catch(error=>console.error(JSON.stringify({level:'error',code:'GRADE_EMAIL_FAILED',message:error.message})));ok(res,{id:String(grade._id),note:grade.score},'Note enregistrée et candidat notifié',201);}));
router.get('/paiements/nupcan/:nupcan',asyncHandler(async(req,res)=>{const application=await Application.findOne({nupcan:String(req.params.nupcan).trim().toUpperCase()}).lean();if(!application)throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const p=await Payment.findOne({applicationId:application._id}).sort({createdAt:-1}).lean();if(!p)return ok(res,null,'Aucun paiement');ok(res,{id:String(p._id),reference_paiement:p.paymentReference,montant:p.amount,methode:p.provider,statut:{paid:'valide',pending:'en_attente',processing:'en_attente',failed:'rejete',cancelled:'rejete',refunded:'rembourse'}[p.status]||p.status,created_at:p.createdAt},'Paiement chargé');}));
router.post('/paiements',authenticationLimiter,required('nupcan','methode'),asyncHandler(async(req,res)=>{const nupcan=String(req.body.nupcan).trim().toUpperCase();const application=await Application.findOne({nupcan}).populate('contestId candidateId');if(!application)throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const contest=application.contestId;if(!contest)throw new AppError(422,'CONTEST_NOT_FOUND','Concours introuvable');if(contest.status==='archived'||(contest.closesAt&&new Date(contest.closesAt)<new Date()))throw new AppError(409,'CONTEST_CLOSED','Ce concours est clôturé');const [requirements,documents]=await Promise.all([DocumentRequirement.find({contestId:contest._id,active:true,required:true,$or:[{programId:null},{programId:application.programId}]}).select('_id').lean(),ApplicationDocument.find({applicationId:application._id}).select('requirementId').lean()]);const submitted=new Set(documents.filter(item=>item.requirementId).map(item=>String(item.requirementId))),missing=requirements.filter(item=>!submitted.has(String(item._id))).length;if(missing)throw new AppError(409,'REQUIRED_DOCUMENTS_MISSING',`${missing} document(s) obligatoire(s) sont encore manquants`);const amount=Number(contest.fee||0),provider=String(req.body.methode).trim().toLowerCase();if(!['airtel_money','moov','gorri'].includes(provider))throw new AppError(422,'INVALID_PAYMENT_PROVIDER','Méthode de paiement invalide');if(amount>0&&provider==='gorri')throw new AppError(422,'INVALID_FREE_PAYMENT','Ce concours n’est pas gratuit');const existing=await Payment.findOne({applicationId:application._id,status:{$in:['pending','processing','paid']}}).sort({createdAt:-1});if(existing)return ok(res,{id:String(existing._id),reference_paiement:existing.paymentReference,montant:existing.amount,methode:existing.provider,statut:legacyPaymentStatus(existing.status)},'Paiement existant réutilisé');const status=amount===0?'paid':'pending',reference=`${amount===0?'FREE':'PAY'}-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,payment=await Payment.create({applicationId:application._id,candidateId:application.candidateId._id,provider,paymentReference:reference,amount,currency:'XAF',status,metadata:{phone:String(req.body.numero_telephone||'').slice(0,30)}});await Notification.create({candidateId:application.candidateId._id,applicationId:application._id,legacyNupcan:nupcan,title:status==='paid'?'Candidature finalisée':'Paiement en attente',body:status==='paid'?'Votre candidature gratuite a été finalisée.':'Votre demande de paiement a été créée et attend la confirmation de l’opérateur.',channel:'in_app'});ok(res,{id:String(payment._id),reference_paiement:reference,montant:amount,methode:provider,statut:legacyPaymentStatus(status)},status==='paid'?'Candidature finalisée':'Paiement initialisé',201);}));
router.get('/paiements',authenticate,requirePermission('view_payments'),asyncHandler(async(req,res)=>{const ids=await scopedApplicationIds(req.admin);const items=await Payment.find(ids?{applicationId:{$in:ids}}:{}).populate('candidateId').populate({path:'applicationId',populate:[{path:'contestId'},{path:'programId'}]}).sort({createdAt:-1}).lean();ok(res,items.map(p=>({id:String(p._id),legacyId:p.legacyId,candidat_nom:p.candidateId?`${p.candidateId.firstName} ${p.candidateId.lastName}`.trim():'',candidat_email:p.candidateId?.email||'',nupcan:p.applicationId?.nupcan||'',concours:p.applicationId?.contestId?.title||'',filiere:p.applicationId?.programId?.name||'',reference:p.paymentReference,transaction_id:p.transactionId,montant:p.amount,devise:p.currency,methode:p.provider,statut:{paid:'valide',pending:'en_attente',processing:'en_attente',failed:'rejete',cancelled:'rejete',refunded:'rembourse'}[p.status]||p.status,date_paiement:p.createdAt,created_at:p.createdAt})),'Paiements complets chargés');}));
router.use('/paiements/:id/status',authenticate,asyncHandler(async(req,_res,next)=>{const payment=await Payment.findById(req.params.id).populate({path:'applicationId',populate:{path:'contestId'}});if(!payment)throw new AppError(404,'PAYMENT_NOT_FOUND','Paiement introuvable');assertContestAccess(req.admin,payment.applicationId.contestId);assertContestWritable(payment.applicationId.contestId);next();}));
router.patch('/paiements/:id/status',authenticate,requirePermission('manage_payments'),asyncHandler(async(req,res)=>{const status={valide:'paid',rejete:'failed',en_attente:'pending'}[req.body.statut]||req.body.status;if(!['paid','failed','pending','processing','cancelled','refunded'].includes(status))throw new AppError(422,'INVALID_PAYMENT_STATUS','Statut de paiement invalide');const item=await Payment.findByIdAndUpdate(req.params.id,{$set:{status}},{new:true,runValidators:true});if(!item)throw new AppError(404,'PAYMENT_NOT_FOUND','Paiement introuvable');ok(res,{id:String(item._id),statut:item.status},'Statut du paiement modifié');}));
router.get('/applications/:nupcan/payment-eligibility', asyncHandler(async (req, res) => {
  const nupcan = String(req.params.nupcan).trim().toUpperCase();
  const application = await Application.findOne({ nupcan }).populate('candidateId contestId programId').lean();
  if (!application) throw new AppError(404, 'APPLICATION_NOT_FOUND', 'Candidature introuvable');
  const [requirements, documents, payment] = await Promise.all([
    DocumentRequirement.find({ contestId: application.contestId._id, active: true, required: true, $or: [{ programId: null }, { programId: application.programId?._id }] }).select('_id').lean(),
    ApplicationDocument.find({ applicationId: application._id }).select('requirementId status').lean(),
    Payment.findOne({ applicationId: application._id }).sort({ createdAt: -1 }).lean()
  ]);
  // Le paiement dépend du dépôt des pièces, pas de leur validation administrative.
  const submitted = new Set(documents.filter(document => document.requirementId).map(document => String(document.requirementId)));
  const missing = requirements.filter(requirement => !submitted.has(String(requirement._id))).length;
  const alreadyPaid = payment?.status === 'paid';
  const candidate = application.candidateId || {};
  const contest = application.contestId || {};
  ok(res, {
    eligible: missing === 0 && !alreadyPaid,
    missing,
    alreadyPaid,
    payment: payment ? { id: String(payment._id), montant: payment.amount, statut: legacyPaymentStatus(payment.status), methode: payment.provider } : null,
    paymentContext: {
      nupcan: application.nupcan,
      candidat: { id: String(candidate._id || ''), nomcan: candidate.lastName || '', prncan: candidate.firstName || '', maican: candidate.email || '', telcan: candidate.phone || '' },
      concours: { id: contest.legacyId || String(contest._id || ''), libcnc: contest.title || '', fracnc: contest.fee || 0, agecnc: contest.maximumAge || 0, debcnc: contest.opensAt || '', fincnc: contest.closesAt || '' }
    }
  }, 'Eligibilité au paiement chargée');
}));
router.use('/applications/:nupcan',asyncHandler(async(req,_res,next)=>{if(req.method!=='PATCH')return next();const application=await Application.findOne({nupcan:String(req.params.nupcan).toUpperCase()}).populate('contestId');if(application)assertContestWritable(application.contestId);next();}));
router.post('/applications', required('contestId','programId','candidate.firstName','candidate.lastName','candidate.phone'), asyncHandler(async (req, res) => ok(res, await createApplication(req.body), 'Brouillon créé', 201)));
router.get('/applications/:nupcan', asyncHandler(async (req, res) => { const item = await Application.findOne({ nupcan: req.params.nupcan.toUpperCase() }).populate('candidateId contestId programId').lean(); if (!item) throw new AppError(404, 'APPLICATION_NOT_FOUND', 'Candidature introuvable'); ok(res, item); }));
router.patch('/applications/:nupcan', asyncHandler(async (req, res) => { const update = {}; if (Array.isArray(req.body.completedSteps)) update.completedSteps = req.body.completedSteps; const item = await Application.findOneAndUpdate({ nupcan: req.params.nupcan.toUpperCase(), status: 'draft' }, update, { new: true, runValidators: true }); if (!item) throw new AppError(404, 'DRAFT_NOT_FOUND', 'Brouillon introuvable'); ok(res, item, 'Brouillon enregistré'); }));
router.post('/payments', required('applicationId','paymentReference','provider','amount'), asyncHandler(async (req, res) => { if (process.env.NODE_ENV === 'production' && req.body.provider === 'development') throw new AppError(400, 'SIMULATION_DISABLED', 'Le paiement simulé est désactivé en production'); const payment = await Payment.findOneAndUpdate({ paymentReference: req.body.paymentReference }, { $setOnInsert: { applicationId: req.body.applicationId, candidateId: req.body.candidateId, provider: req.body.provider, paymentReference: req.body.paymentReference, amount: req.body.amount, currency: req.body.currency || 'XAF', status: 'pending' } }, { upsert: true, new: true, runValidators: true }); ok(res, payment, 'Paiement initialisé', 201); }));
router.get('/admin/applications', authenticate, scopeEstablishment, asyncHandler(async (req, res) => { const query = {}; if (req.query.status) query.status = req.query.status; if (req.query.contestId) query.contestId = req.query.contestId; if (req.query.nupcan) query.nupcan = req.query.nupcan.toUpperCase(); ok(res, await Application.find(query).populate('candidateId', 'firstName lastName phone').sort({ createdAt: -1 }).limit(100).lean()); }));
router.get('/admin/applications/:id',authenticate,requirePermission('view_applications'),asyncHandler(async(req,res)=>{const application=await scopedApplication(req.admin,req.params.id);const [documents,payment,grades]=await Promise.all([ApplicationDocument.find({applicationId:application._id}).sort({createdAt:-1}).lean(),Payment.findOne({applicationId:application._id}).sort({createdAt:-1}).lean(),Grade.find({applicationId:application._id}).populate('subjectId').lean()]);ok(res,{application,candidate:application.candidateId,contest:application.contestId,program:application.programId,documents:documents.map(documentView),payment,grades,summary:gradeSummary(grades),readOnly:applicationReadOnly(application)},'Candidature chargée');}));
router.patch('/admin/applications/:id/status',authenticate,requirePermission('manage_applications'),required('status'),asyncHandler(async(req,res)=>{const application=await scopedApplication(req.admin,req.params.id);assertContestWritable(application.contestId);const status={en_attente:'under_review',valide:'approved',rejete:'rejected'}[req.body.status]||req.body.status;if(!['submitted','under_review','approved','rejected','cancelled'].includes(status))throw new AppError(422,'INVALID_APPLICATION_STATUS','Statut de candidature invalide');application.status=status;application.statusHistory.push({status,reason:String(req.body.reason||'').trim(),changedBy:req.admin._id});await application.save();await Notification.create({candidateId:application.candidateId._id,applicationId:application._id,legacyNupcan:application.nupcan,title:'Statut de candidature mis à jour',body:`Votre candidature est maintenant : ${status}.`,channel:'in_app'});ok(res,{id:String(application._id),status:application.status},'Statut mis à jour');}));
router.patch('/admin/applications/:id/candidate',authenticate,requirePermission('manage_applications'),asyncHandler(async(req,res)=>{const application=await scopedApplication(req.admin,req.params.id);assertContestWritable(application.contestId);const update={};for(const [source,target] of Object.entries({nomcan:'lastName',prncan:'firstName',maican:'email',telcan:'phone',ldncan:'birthPlace'}))if(req.body[source]!=null)update[target]=String(req.body[source]).trim();if(update.email){update.email=update.email.toLowerCase();if(await Candidate.exists({_id:{$ne:application.candidateId._id},email:update.email}))throw new AppError(409,'CANDIDATE_EMAIL_ALREADY_EXISTS','Cette adresse e-mail appartient déjà à un autre candidat');}if(req.body.dtncan)update.birthDate=new Date(req.body.dtncan);const candidate=await Candidate.findByIdAndUpdate(application.candidateId._id,{$set:update},{new:true,runValidators:true}).lean();ok(res,candidate,'Informations du candidat modifiées');}));
router.delete('/admin/applications/:id',authenticate,requirePermission('manage_applications'),asyncHandler(async(req,res)=>{const application=await scopedApplication(req.admin,req.params.id);assertContestWritable(application.contestId);if(application.status!=='draft')throw new AppError(409,'APPLICATION_DELETE_FORBIDDEN','Seul un brouillon peut être supprimé');application.status='cancelled';application.statusHistory.push({status:'cancelled',reason:'Brouillon annulé par administration',changedBy:req.admin._id});await application.save();ok(res,{id:String(application._id),status:'cancelled'},'Brouillon annulé');}));
router.put('/admin/grades/:id',authenticate,requirePermission('enter_grades'),required('score'),asyncHandler(async(req,res)=>{const grade=await Grade.findById(req.params.id).populate({path:'applicationId',populate:{path:'contestId'}});if(!grade)throw new AppError(404,'GRADE_NOT_FOUND','Note introuvable');assertContestAccess(req.admin,grade.applicationId.contestId);assertContestWritable(grade.applicationId.contestId);const score=Number(req.body.score);if(!Number.isFinite(score)||score<0||score>grade.maximumScore)throw new AppError(422,'INVALID_GRADE','Note invalide');grade.score=score;grade.enteredBy=req.admin._id;grade.validatedAt=undefined;grade.validatedBy=undefined;await grade.save();ok(res,grade,'Note modifiée');}));
router.delete('/admin/grades/:id',authenticate,requirePermission('enter_grades'),asyncHandler(async(req,res)=>{const grade=await Grade.findById(req.params.id).populate({path:'applicationId',populate:{path:'contestId'}});if(!grade)throw new AppError(404,'GRADE_NOT_FOUND','Note introuvable');assertContestAccess(req.admin,grade.applicationId.contestId);assertContestWritable(grade.applicationId.contestId);await grade.deleteOne();ok(res,{id:req.params.id},'Note supprimée');}));
router.post('/admin/grades/batch',authenticate,requirePermission('enter_grades'),required('grades'),asyncHandler(async(req,res)=>{if(!Array.isArray(req.body.grades)||!req.body.grades.length)throw new AppError(422,'GRADES_REQUIRED','Aucune note fournie');const saved=[];for(const input of req.body.grades){const application=await scopedApplication(req.admin,input.applicationId||input.nupcan);assertContestWritable(application.contestId);const subject=await Subject.findOne(idFilter(String(input.subjectId)));if(!subject)throw new AppError(422,'INVALID_SUBJECT','Matière invalide');const score=Number(input.score);if(!Number.isFinite(score)||score<0||score>20)throw new AppError(422,'INVALID_GRADE','Chaque note doit être comprise entre 0 et 20');saved.push(await Grade.findOneAndUpdate({applicationId:application._id,subjectId:subject._id},{$set:{score,maximumScore:20,coefficient:Number(input.coefficient||subject.coefficient||1),enteredBy:req.admin._id},$unset:{validatedAt:1,validatedBy:1}},{upsert:true,new:true,runValidators:true}));}ok(res,{count:saved.length,grades:saved},'Notes enregistrées',201);}));
router.post('/notes/envoyer-resultats',authenticate,requirePermission('validate_grades'),required('candidat_id','concours_id'),asyncHandler(async(req,res)=>{const [candidate,contest]=await Promise.all([Candidate.findOne(idFilter(String(req.body.candidat_id))).lean(),Contest.findOne(contestFilter(String(req.body.concours_id))).lean()]);if(!candidate||!contest)throw new AppError(404,'SELECTION_NOT_FOUND','Candidat ou concours introuvable');assertContestAccess(req.admin,contest);const application=await Application.findOne({candidateId:candidate._id,contestId:contest._id}).lean();if(!application)throw new AppError(404,'APPLICATION_NOT_FOUND','Candidature introuvable');const grades=await Grade.find({applicationId:application._id}).populate('subjectId').lean();if(!grades.length)throw new AppError(422,'GRADES_REQUIRED','Aucune note à envoyer');const average=gradeSummary(grades).average;await Notification.create({candidateId:candidate._id,applicationId:application._id,legacyNupcan:application.nupcan,title:'Résultats disponibles',body:`Vos résultats pour ${contest.title} sont disponibles. Moyenne : ${average==null?'non calculée':`${average}/20`}.`,channel:'in_app'});let emailSent=false;if(candidate.email){await emailService.sendEmail(candidate.email,`Résultats - ${contest.title}`,`<p>Bonjour ${candidate.firstName},</p><p>Vos résultats sont disponibles dans votre espace candidat.</p>`);emailSent=true;}ok(res,{emailSent,average},'Résultats envoyés au candidat');}));
router.post('/admin/contests/:id/publish-results',authenticate,requirePermission('validate_grades'),asyncHandler(async(req,res)=>{const contest=await Contest.findOne(contestFilter(req.params.id));if(!contest)throw new AppError(404,'CONTEST_NOT_FOUND','Concours introuvable');assertContestAccess(req.admin,contest);if(contest.closesAt&&new Date(contest.closesAt)>new Date())throw new AppError(409,'CONTEST_STILL_OPEN','Les résultats ne peuvent être publiés avant la clôture');const applications=await Application.find({contestId:contest._id}).populate('candidateId').lean(),ids=applications.map(item=>item._id),now=new Date();await Grade.updateMany({applicationId:{$in:ids}},{$set:{validatedBy:req.admin._id,validatedAt:now}});contest.resultsPublishedAt=now;contest.status='archived';await contest.save();const notifications=applications.map(item=>({candidateId:item.candidateId?._id,applicationId:item._id,legacyNupcan:item.nupcan,title:'Résultats publiés',body:`Les résultats du concours ${contest.title} sont disponibles.`,channel:'in_app'}));if(notifications.length)await Notification.insertMany(notifications);const emailResults=await Promise.allSettled(applications.filter(item=>item.candidateId?.email).map(item=>emailService.sendEmail(item.candidateId.email,`Résultats – ${contest.title}`,`<p>Bonjour ${item.candidateId.firstName},</p><p>Vos résultats sont disponibles dans votre espace candidat.</p>`)));ok(res,{applications:applications.length,emailsSent:emailResults.filter(item=>item.status==='fulfilled').length,publishedAt:now},'Résultats publiés et candidats notifiés');}));
router.get('/admin/archives',authenticate,requirePermission('view_applications'),asyncHandler(async(req,res)=>{await archiveExpiredContests();const query={status:'archived'};if(req.admin.role!=='super_admin')query.establishmentId={$in:assignedEstablishments(req.admin)};const contests=await Contest.find(query).populate('establishmentId').sort({closesAt:-1}).lean();const totals=await Application.aggregate([{$match:{contestId:{$in:contests.map(item=>item._id)}}},{$group:{_id:'$contestId',count:{$sum:1}}}]);const count=new Map(totals.map(item=>[String(item._id),item.count]));ok(res,contests.map(item=>({...toLegacyContest(item),total_candidatures:count.get(String(item._id))||0,readOnly:true})),'Archives chargées');}));
router.get('/admin/reports/applications/:id/transcript.pdf',authenticate,requirePermission('view_reports'),asyncHandler(async(req,res)=>{const application=await scopedApplication(req.admin,req.params.id),grades=await Grade.find({applicationId:application._id}).populate('subjectId').lean(),summary=gradeSummary(grades);res.type('application/pdf').set('Content-Disposition',`attachment; filename="releve-${application.nupcan}.pdf"`);const pdf=new PDFDocument({margin:48});pdf.pipe(res);pdf.fontSize(18).text('GABCONCOURS – RELEVÉ DE NOTES',{align:'center'}).moveDown();pdf.fontSize(11).text(`Candidat : ${application.candidateId.firstName} ${application.candidateId.lastName}`).text(`NUPCAN : ${application.nupcan}`).text(`Concours : ${application.contestId.title}`).text(`Filière : ${application.programId.name}`).moveDown();grades.forEach(item=>pdf.text(`${item.subjectId?.name||'Matière'} : ${item.score}/${item.maximumScore}  (coef. ${item.coefficient})`));pdf.moveDown().fontSize(14).text(`Moyenne générale : ${summary.average==null?'Non calculée':`${summary.average}/20`}`,{align:'right'});pdf.end();}));
router.get('/admin/reports/contests/:id/transcripts.pdf',authenticate,requirePermission('view_reports'),asyncHandler(async(req,res)=>{const contest=await Contest.findOne(contestFilter(req.params.id));if(!contest)throw new AppError(404,'CONTEST_NOT_FOUND','Concours introuvable');assertContestAccess(req.admin,contest);const applications=await Application.find({contestId:contest._id}).populate('candidateId programId').sort({nupcan:1}).lean(),grades=await Grade.find({applicationId:{$in:applications.map(item=>item._id)}}).populate('subjectId').lean();res.type('application/pdf').set('Content-Disposition',`attachment; filename="releves-${contest.slug}.pdf"`);const pdf=new PDFDocument({margin:48});pdf.pipe(res);applications.forEach((application,index)=>{if(index)pdf.addPage();const items=grades.filter(item=>String(item.applicationId)===String(application._id)),summary=gradeSummary(items);pdf.fontSize(17).text('GABCONCOURS – RELEVÉ DE NOTES',{align:'center'}).moveDown().fontSize(11).text(`Candidat : ${application.candidateId?.firstName||''} ${application.candidateId?.lastName||''}`).text(`NUPCAN : ${application.nupcan}`).text(`Concours : ${contest.title}`).text(`Filière : ${application.programId?.name||''}`).moveDown();items.forEach(item=>pdf.text(`${item.subjectId?.name||'Matière'} : ${item.score}/${item.maximumScore} (coef. ${item.coefficient})`));pdf.moveDown().fontSize(14).text(`Moyenne : ${summary.average==null?'Non calculée':`${summary.average}/20`}`,{align:'right'});});if(!applications.length)pdf.text('Aucune candidature pour ce concours.');pdf.end();}));
module.exports = router;
