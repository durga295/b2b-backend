import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import QRCode from 'qrcode';
import mongoose, { Types } from 'mongoose';
import { z } from 'zod';
import { env } from '../config/env';
import { AuditLog, Certificate, FraudAlert, Order, Organization, Passport, Product, Rfq, ServiceCase, SupplyEvent, User } from '../models';
import { allow, auth } from '../middleware/auth';

const router = Router();
const escapeRegex = (value: string) => value.split('').map((c) => '\\^$.*+?()[]{}|'.includes(c) ? `\\${c}` : c).join('');
const wrap = (fn: (req: any, res: any) => Promise<any>) => (req: any, res: any, next: any) => Promise.resolve(fn(req, res)).catch(next);
const record = (req: any, action: string, entityType: string, entityId: string, details?: any) => AuditLog.create({ actorId: req.user?.id, action, entityType, entityId, details });
const storageRoot = path.resolve(process.cwd(), env.uploadDir); fs.mkdirSync(storageRoot, { recursive: true });
const upload = multer({ storage: multer.diskStorage({ destination: storageRoot, filename: (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`) }), limits: { fileSize: 8 * 1024 * 1024 } });

router.get('/health', (_req, res) => res.json({ status: 'ok', service: 'b2b-dpp-api' }));

router.post('/auth/register', wrap(async (req, res) => {
  const data = z.object({ name: z.string().min(2), email: z.string().email(), password: z.string().min(8), organizationName: z.string().min(2).optional(), role: z.enum(['manufacturer','supplier','warehouse','logistics','buyer','inspector','service_center']).default('buyer') }).parse(req.body);
  if (await User.exists({ email: data.email.toLowerCase() })) return res.status(409).json({ error: 'Email is already registered' });
  let org = data.organizationName ? await Organization.create({ name: data.organizationName, type: data.role }) : null;
  if (!org) org = await Organization.create({ name: `${data.name}'s organization`, type: data.role });
  const user = await User.create({ name: data.name, email: data.email, passwordHash: await bcrypt.hash(data.password, 12), role: data.role, organizationId: org._id });
  const token = jwt.sign({ id: user.id, role: user.role, organizationId: String(org._id) }, env.jwtSecret, { expiresIn: env.jwtExpiresIn } as jwt.SignOptions);
  res.status(201).json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, organization: org.name, organizationId: String(org._id) } });
}));
router.post('/auth/login', wrap(async (req, res) => {
  const { email, password } = z.object({ email: z.string().email(), password: z.string().min(1) }).parse(req.body);
  const user: any = await User.findOne({ email: email.toLowerCase(), active: true }).populate('organizationId');
  if (!user || !(await user.checkPassword(password))) return res.status(401).json({ error: 'Email or password is incorrect' });
  const orgId = user.organizationId?._id?.toString() || user.organizationId?.toString();
  const token = jwt.sign({ id: user.id, role: user.role, organizationId: orgId }, env.jwtSecret, { expiresIn: env.jwtExpiresIn } as jwt.SignOptions);
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, organization: user.organizationId?.name, organizationId: orgId } });
}));
router.post('/auth/logout', auth, (_req, res) => res.json({ message: 'Signed out. Remove the token from the client.' }));
router.get('/auth/me', auth, wrap(async (req, res) => { const user = await User.findById(req.user!.id).select('-passwordHash').populate('organizationId'); if (!user) return res.status(404).json({ error: 'User not found' }); res.json(user); }));

router.get('/organizations/:id', auth, wrap(async (req, res) => { const org = await Organization.findById(req.params.id); if (!org) return res.status(404).json({ error: 'Organization not found' }); res.json(org); }));
router.patch('/organizations/:id', auth, wrap(async (req, res) => { if (req.user!.role !== 'admin' && req.user!.organizationId !== req.params.id) return res.status(403).json({ error: 'Organization access denied' }); const org = await Organization.findByIdAndUpdate(req.params.id, { $set: { name: req.body.name, address: req.body.address } }, { new: true, runValidators: true }); res.json(org); }));

router.get('/products', wrap(async (req, res) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Product catalogue is temporarily unavailable.' });
  }
  const page = Math.max(1, Number(req.query.page) || 1), limit = Math.min(50, Math.max(1, Number(req.query.limit) || 12));
  const filter: any = { active: true };
  if (req.query.category) filter.category = String(req.query.category);
  if (req.query.supplier) {
    const supplierId = String(req.query.supplier);
    if (!Types.ObjectId.isValid(supplierId)) return res.status(400).json({ error: 'Invalid supplier identifier' });
    filter.manufacturerId = supplierId;
  }
  const search = String(req.query.q || '').trim();
  if (search) {
    const pattern = new RegExp(escapeRegex(search), 'i');
    const orgIds = await Organization.find({ name: pattern }).distinct('_id');
    filter.$or = [
      { name: pattern },
      { sku: pattern },
      { category: pattern },
      { description: pattern },
      { manufacturerId: { $in: orgIds } }
    ];
  }
  const [rawItems, total] = await Promise.all([
    Product.find(filter).populate('manufacturerId', 'name').sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
    Product.countDocuments(filter)
  ]);
  const productIds = rawItems.map((item: any) => item._id);
  const passportRows = productIds.length
    ? await Passport.aggregate([
        { $match: { productId: { $in: productIds }, status: 'active' } },
        { $sort: { createdAt: -1 } },
        { $group: { _id: '$productId', count: { $sum: 1 }, samplePublicId: { $first: '$publicId' } } }
      ])
    : [];
  const passportByProduct = new Map<string, { count: number; samplePublicId: string }>(
    passportRows.map((row: any) => [String(row._id), { count: row.count, samplePublicId: row.samplePublicId }])
  );
  const items = rawItems.map((item: any) => {
    const passportMeta = passportByProduct.get(String(item._id));
    return {
      ...item,
      passportCount: passportMeta?.count ?? 0,
      samplePassportId: passportMeta?.samplePublicId ?? null
    };
  });
  res.json({ items, page, limit, total, pages: Math.ceil(total / limit) });
}));
router.get('/products/:id', wrap(async (req, res) => { const product = await Product.findById(req.params.id).populate('manufacturerId', 'name address'); if (!product) return res.status(404).json({ error: 'Product not found' }); res.json(product); }));
router.get('/products/:id/passports', auth, wrap(async (req, res) => {
  const product: any = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ error: 'Product not found' });
  res.json(await Passport.find({ productId: product._id, status: 'active' }).select('publicId serialNumber batchNumber status createdAt').populate('productId', 'name sku').sort({ createdAt: -1 }));
}));
router.post('/products', auth, allow('manufacturer'), wrap(async (req, res) => {
  const data = z.object({ sku: z.string().min(1), name: z.string().min(2), category: z.string().min(2), description: z.string().optional(), specifications: z.record(z.any()).optional(), price: z.coerce.number().nonnegative().default(0), currency: z.string().default('INR'), availableQuantity: z.coerce.number().int().nonnegative().default(0), sustainability: z.object({ carbonKg: z.coerce.number().nonnegative().optional(), recyclabilityScore: z.coerce.number().min(0).max(100).optional(), repairabilityScore: z.coerce.number().min(0).max(100).optional() }).optional() }).parse(req.body);
  const product = await Product.create({ ...data, manufacturerId: req.user!.organizationId }); res.status(201).json(product);
}));
router.patch('/products/:id', auth, allow('manufacturer'), wrap(async (req, res) => { const p = await Product.findOne({ _id: req.params.id, manufacturerId: req.user!.organizationId }); if (!p) return res.status(404).json({ error: 'Product not found or not owned by your organization' }); Object.assign(p, req.body); await p.save(); res.json(p); }));
router.delete('/products/:id', auth, allow('manufacturer'), wrap(async (req, res) => { const p = await Product.findOneAndUpdate({ _id: req.params.id, manufacturerId: req.user!.organizationId }, { active: false }, { new: true }); if (!p) return res.status(404).json({ error: 'Product not found' }); res.json({ message: 'Product archived' }); }));
router.get('/suppliers/:id/products', wrap(async (req, res) => { const products = await Product.find({ manufacturerId: req.params.id, active: true }); res.json({ items: products }); }));
router.get('/suppliers/:id/ratings', wrap(async (_req, res) => res.json({ rating: null, reviews: 0, message: 'Supplier ratings are not yet collected in this MVP' })));

router.post('/passports', auth, allow('manufacturer'), wrap(async (req, res) => {
  const data = z.object({ productId: z.string(), serialNumber: z.string().min(1), batchNumber: z.string().optional(), rawMaterialSources: z.array(z.string()).optional(), warranty: z.object({ durationMonths: z.coerce.number().nonnegative().optional(), startsAt: z.coerce.date().optional(), endsAt: z.coerce.date().optional() }).optional(), sustainability: z.object({ carbonKg: z.coerce.number().nonnegative().optional(), recyclabilityScore: z.coerce.number().min(0).max(100).optional(), repairabilityScore: z.coerce.number().min(0).max(100).optional() }).optional() }).parse(req.body);
  const product = await Product.findOne({ _id: data.productId, manufacturerId: req.user!.organizationId }); if (!product) return res.status(404).json({ error: 'Product not found in your organization' });
  const duplicate = await Passport.findOne({ serialNumber: data.serialNumber });
  if (duplicate) { await FraudAlert.create({ type: 'duplicate_serial', message: `Duplicate serial ${data.serialNumber} was submitted`, passportId: duplicate._id, serialNumber: data.serialNumber }); return res.status(409).json({ error: 'Serial number already exists; a counterfeit alert was created' }); }
  const passport = await Passport.create({ ...data, publicId: randomUUID(), createdBy: req.user!.id, lastModifiedBy: req.user!.id });
  await SupplyEvent.create({ passportId: passport._id, type: 'manufacturing', actorId: req.user!.id, organizationId: req.user!.organizationId, notes: 'Passport issued' });
  await record(req, 'passport.created', 'passport', passport.id); res.status(201).json(passport);
}));
router.get('/passports/:id', auth, wrap(async (req, res) => { const passport = await Passport.findOne({ $or: [{ _id: req.params.id }, { publicId: req.params.id }] }).populate({ path: 'productId', populate: { path: 'manufacturerId', select: 'name' } }); if (!passport) return res.status(404).json({ error: 'Passport not found' }); const [events, certificates] = await Promise.all([SupplyEvent.find({ passportId: passport._id }).populate('organizationId', 'name').sort({ occurredAt: 1 }), Certificate.find({ passportId: passport._id }).select('-filePath')]); res.json({ passport, events, certificates }); }));
router.patch('/passports/:id', auth, allow('manufacturer'), wrap(async (req, res) => { const p: any = await Passport.findById(req.params.id).populate({ path: 'productId' }); if (!p || String(p.productId.manufacturerId) !== req.user!.organizationId) return res.status(404).json({ error: 'Passport not found' }); const allowedFields = ['batchNumber','rawMaterialSources','warranty','sustainability','status']; for (const key of allowedFields) if (key in req.body) p[key] = req.body[key]; p.lastModifiedBy = req.user!.id; await p.save(); await record(req, 'passport.updated', 'passport', p.id, { fields: Object.keys(req.body) }); res.json(p); }));
router.get('/verify/:publicId', wrap(async (req, res) => { const passport: any = await Passport.findOne({ $or: [{ publicId: req.params.publicId }, { serialNumber: req.params.publicId }] }).populate({ path: 'productId', populate: { path: 'manufacturerId', select: 'name' } }); if (!passport) return res.status(404).json({ authentic: false, error: 'Passport not found' }); const [events, certificates] = await Promise.all([SupplyEvent.find({ passportId: passport._id }).sort({ occurredAt: 1 }).select('-metadata'), Certificate.find({ passportId: passport._id, status: 'valid' }).select('title issuer issuedAt expiresAt')]); res.json({ authentic: passport.status === 'active', passport, events, certificates }); }));
router.get('/passports/:id/qr', auth, wrap(async (req, res) => { const p = await Passport.findById(req.params.id); if (!p) return res.status(404).json({ error: 'Passport not found' }); res.json({ url: `${env.publicAppUrl}/verify/${p.publicId}`, dataUrl: await QRCode.toDataURL(`${env.publicAppUrl}/verify/${p.publicId}`) }); }));
router.get('/passports/:id/events', auth, wrap(async (req, res) => res.json(await SupplyEvent.find({ passportId: req.params.id }).sort({ occurredAt: 1 }).populate('organizationId', 'name'))));
router.get('/passports/:id/timeline', wrap(async (req, res) => res.json(await SupplyEvent.find({ passportId: req.params.id }).sort({ occurredAt: 1 }).populate('organizationId', 'name'))));
router.get('/events', auth, wrap(async (req, res) => {
  const filter: any = {};
  if (req.query.passportId) filter.passportId = req.query.passportId;
  if (req.query.type) filter.type = req.query.type;
  if (req.query.from || req.query.to) filter.occurredAt = { ...(req.query.from ? { $gte: new Date(String(req.query.from)) } : {}), ...(req.query.to ? { $lte: new Date(String(req.query.to)) } : {}) };
  if (req.user!.role !== 'admin') filter.organizationId = req.user!.organizationId;
  const items = await SupplyEvent.find(filter).populate('passportId').sort({ occurredAt: -1 }).limit(200);
  res.json({ items });
}));
router.post('/passports/:id/events', auth, allow('manufacturer','supplier','warehouse','logistics','inspector','service_center'), wrap(async (req, res) => {
  const data = z.object({ type: z.enum(['manufacturing','supplier_stock','warehouse','logistics','sale','warranty','repair','recycling','inspection']), location: z.string().optional(), notes: z.string().optional(), metadata: z.record(z.any()).optional(), occurredAt: z.coerce.date().optional() }).parse(req.body);
  const passport = await Passport.findById(req.params.id); if (!passport) return res.status(404).json({ error: 'Passport not found' });
  if (data.type === 'sale' && req.user!.role !== 'manufacturer' && req.user!.role !== 'admin') return res.status(403).json({ error: 'Only the seller can record a sale' });
  const event = await SupplyEvent.create({ ...data, passportId: passport._id, actorId: req.user!.id, organizationId: req.user!.organizationId }); await record(req, `event.${data.type}`, 'passport', passport.id); res.status(201).json(event);
}));
router.post('/passports/:id/certificates', auth, allow('manufacturer','inspector'), upload.single('file'), wrap(async (req, res) => { const p = await Passport.findById(req.params.id); if (!p) return res.status(404).json({ error: 'Passport not found' }); const c = await Certificate.create({ passportId: p._id, title: req.body.title || req.file?.originalname || 'Certificate', issuer: req.body.issuer, issuedAt: req.body.issuedAt || undefined, expiresAt: req.body.expiresAt || undefined, fileName: req.file?.originalname, filePath: req.file?.filename, uploadedBy: req.user!.id }); res.status(201).json({ ...c.toObject(), downloadUrl: c.filePath ? `/api/v1/certificates/${c.id}/file` : undefined }); }));
router.get('/passports/:id/certificates', auth, wrap(async (req, res) => res.json(await Certificate.find({ passportId: req.params.id }).select('-filePath'))));
router.get('/certificates/:id/file', auth, wrap(async (req, res) => { const c: any = await Certificate.findById(req.params.id); if (!c?.filePath) return res.status(404).json({ error: 'File not found' }); const p: any = await Passport.findById(c.passportId).populate('productId'); if (!p) return res.status(404).json({ error: 'Passport not found' }); if (req.user!.role !== 'admin' && req.user!.role !== 'inspector' && String(p.productId.manufacturerId) !== req.user!.organizationId) return res.status(403).json({ error: 'Certificate file access denied' }); res.sendFile(path.join(storageRoot, path.basename(c.filePath))); }));
router.delete('/certificates/:id', auth, allow('manufacturer','inspector'), wrap(async (req, res) => { const c = await Certificate.findByIdAndUpdate(req.params.id, { status: 'revoked' }, { new: true }); if (!c) return res.status(404).json({ error: 'Certificate not found' }); await record(req, 'certificate.revoked', 'certificate', c.id); res.json(c); }));

router.post('/rfqs', auth, allow('buyer'), wrap(async (req, res) => { const d = z.object({ productId: z.string(), quantity: z.coerce.number().int().positive(), message: z.string().optional() }).parse(req.body); if (!await Product.exists({ _id: d.productId, active: true })) return res.status(404).json({ error: 'Product not found' }); res.status(201).json(await Rfq.create({ ...d, buyerId: req.user!.id })); }));
router.get('/rfqs', auth, wrap(async (req, res) => {
  let filter: any = req.user!.role === 'admin' ? {} : req.user!.role === 'buyer' ? { buyerId: req.user!.id } : { productId: { $in: await Product.find({ manufacturerId: req.user!.organizationId }).distinct('_id') } };
  const items = await Rfq.find(filter).populate('buyerId', 'name email').populate('productId').sort({ createdAt: -1 }); res.json({ items });
}));
router.get('/rfqs/:id', auth, wrap(async (req, res) => { const item = await Rfq.findById(req.params.id).populate('productId').populate('buyerId', 'name'); if (!item) return res.status(404).json({ error: 'RFQ not found' }); res.json(item); }));
router.patch('/rfqs/:id/status', auth, wrap(async (req, res) => { const r: any = await Rfq.findById(req.params.id); if (!r) return res.status(404).json({ error: 'RFQ not found' }); if (req.user!.role !== 'admin' && req.user!.id !== String(r.buyerId)) return res.status(403).json({ error: 'RFQ access denied' }); r.status = z.enum(['open','quoted','accepted','closed']).parse(req.body.status); await r.save(); res.json(r); }));
router.post('/rfqs/:id/quotes', auth, allow('manufacturer'), wrap(async (req, res) => { const r: any = await Rfq.findById(req.params.id).populate('productId'); if (!r || String(r.productId.manufacturerId) !== req.user!.organizationId) return res.status(404).json({ error: 'RFQ not found for your organization' }); r.quote = z.object({ amount: z.coerce.number().nonnegative(), currency: z.string().default('INR'), message: z.string().optional(), validUntil: z.coerce.date().optional() }).parse(req.body); r.quote.sellerId = req.user!.organizationId; r.status = 'quoted'; await r.save(); res.json(r); }));
router.post('/orders', auth, allow('buyer'), wrap(async (req, res) => { const d = z.object({ productId: z.string(), quantity: z.coerce.number().int().positive(), passportId: z.string().optional() }).parse(req.body); const p: any = await Product.findOne({ _id: d.productId, active: true }); if (!p) return res.status(404).json({ error: 'Product not found' }); if (p.availableQuantity < d.quantity) return res.status(400).json({ error: 'Requested quantity exceeds available stock' }); p.availableQuantity -= d.quantity; await p.save(); const order = await Order.create({ buyerId: req.user!.id, sellerId: p.manufacturerId, productId: p._id, quantity: d.quantity, unitPrice: p.price, total: p.price * d.quantity, passportId: d.passportId }); if (d.passportId) await SupplyEvent.create({ passportId: d.passportId, type: 'sale', actorId: req.user!.id, notes: `Order ${order.id} placed`, metadata: { orderId: order.id } }); res.status(201).json(order); }));
router.get('/orders', auth, wrap(async (req, res) => { const filter: any = req.user!.role === 'admin' ? {} : req.user!.role === 'buyer' ? { buyerId: req.user!.id } : { sellerId: req.user!.organizationId }; res.json({ items: await Order.find(filter).populate('productId').populate('buyerId', 'name').sort({ createdAt: -1 }) }); }));
router.get('/orders/:id', auth, wrap(async (req, res) => { const o: any = await Order.findById(req.params.id).populate('productId'); if (!o) return res.status(404).json({ error: 'Order not found' }); const isParty = String(o.buyerId) === req.user!.id || String(o.sellerId) === req.user!.organizationId; if (!isParty && req.user!.role !== 'admin') return res.status(403).json({ error: 'Order access denied' }); res.json(o); }));
router.patch('/orders/:id/status', auth, wrap(async (req, res) => { const o: any = await Order.findById(req.params.id); if (!o) return res.status(404).json({ error: 'Order not found' }); if (req.user!.role !== 'admin' && String(o.sellerId) !== req.user!.organizationId) return res.status(403).json({ error: 'Only the seller can update this order' }); o.status = z.enum(['confirmed','shipped','delivered','cancelled']).parse(req.body.status); await o.save(); res.json(o); }));

router.get('/admin/transactions/summary', auth, allow('admin'), wrap(async (_req, res) => {
  const grouped = await Order.aggregate([{ $group: { _id: '$status', count: { $sum: 1 }, value: { $sum: '$total' } } }]);
  const summary: Record<string, { count: number; value: number }> = {};
  for (const status of ['placed','confirmed','shipped','delivered','cancelled']) summary[status] = { count: 0, value: 0 };
  for (const row of grouped) summary[row._id] = { count: row.count, value: row.value };
  res.json({ total: Object.values(summary).reduce((sum, row) => sum + row.count, 0), grossValue: Object.values(summary).reduce((sum, row) => sum + row.value, 0), statuses: summary });
}));
router.get('/admin/transactions', auth, allow('admin'), wrap(async (req, res) => {
  const page = Math.max(1, Number(req.query.page) || 1);
  const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 20));
  const filter: any = {};
  if (req.query.status && req.query.status !== 'all') filter.status = z.enum(['placed','confirmed','shipped','delivered','cancelled']).parse(req.query.status);
  const search = String(req.query.search || '').trim();
  if (search) {
    const pattern = new RegExp(escapeRegex(search), 'i');
    const [buyerIds, productIds] = await Promise.all([
      User.find({ $or: [{ name: pattern }, { email: pattern }] }).distinct('_id'),
      Product.find({ $or: [{ name: pattern }, { sku: pattern }] }).distinct('_id')
    ]);
    const matches: any[] = [{ buyerId: { $in: buyerIds } }, { productId: { $in: productIds } }];
    if (Types.ObjectId.isValid(search)) matches.push({ _id: new Types.ObjectId(search) });
    filter.$or = matches;
  }
  const [items, total] = await Promise.all([
    Order.find(filter).populate('productId', 'name sku').populate({ path: 'buyerId', select: 'name email organizationId', populate: { path: 'organizationId', select: 'name' } }).populate('sellerId', 'name').sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit),
    Order.countDocuments(filter)
  ]);
  res.json({ items, page, limit, total, pages: Math.max(1, Math.ceil(total / limit)) });
}));
router.patch('/admin/transactions/:id/status', auth, allow('admin'), wrap(async (req, res) => {
  const status = z.enum(['placed','confirmed','shipped','delivered','cancelled']).parse(req.body.status);
  const order: any = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ error: 'Transaction not found' });
  const previousStatus = order.status;
  order.status = status;
  await order.save();
  await record(req, 'transaction.status_updated', 'order', order.id, { previousStatus, status });
  const updated = await Order.findById(order.id).populate('productId', 'name sku').populate({ path: 'buyerId', select: 'name email organizationId', populate: { path: 'organizationId', select: 'name' } }).populate('sellerId', 'name');
  res.json(updated);
}));

router.post('/passports/:id/service-cases', auth, allow('buyer','service_center'), wrap(async (req, res) => { const p = await Passport.findById(req.params.id); if (!p) return res.status(404).json({ error: 'Passport not found' }); const d = z.object({ type: z.enum(['warranty','repair','recycling']), description: z.string().optional() }).parse(req.body); const c = await ServiceCase.create({ ...d, passportId: p._id, ownerId: req.user!.id }); await SupplyEvent.create({ passportId: p._id, type: d.type === 'warranty' ? 'warranty' : d.type, actorId: req.user!.id, notes: d.description || `${d.type} case opened` }); res.status(201).json(c); }));
router.get('/service-cases', auth, wrap(async (req, res) => { const filter: any = req.user!.role === 'admin' || req.user!.role === 'service_center' ? {} : { ownerId: req.user!.id }; res.json({ items: await ServiceCase.find(filter).populate('passportId').sort({ createdAt: -1 }) }); }));
router.patch('/service-cases/:id', auth, allow('service_center'), wrap(async (req, res) => { const c: any = await ServiceCase.findById(req.params.id); if (!c) return res.status(404).json({ error: 'Service case not found' }); c.status = z.enum(['open','in_progress','resolved','rejected']).parse(req.body.status); if (req.body.resolution !== undefined) c.resolution = String(req.body.resolution); await c.save(); res.json(c); }));

router.get('/analytics/overview', auth, wrap(async (req, res) => { const org = req.user!.organizationId; const scope = req.user!.role === 'admin' ? {} : req.user!.role === 'buyer' ? { buyerId: req.user!.id } : { manufacturerId: org }; const [products, passports, orders, rfqs, alerts] = await Promise.all([Product.countDocuments(req.user!.role === 'admin' ? {} : { manufacturerId: org, active: true }), Passport.countDocuments(req.user!.role === 'admin' ? {} : { createdBy: req.user!.id }), Order.countDocuments(req.user!.role === 'admin' ? {} : req.user!.role === 'buyer' ? { buyerId: req.user!.id } : { sellerId: org }), Rfq.countDocuments(req.user!.role === 'admin' ? {} : { buyerId: req.user!.id }), FraudAlert.countDocuments({ status: 'open' })]); res.json({ products, passports, orders, rfqs, openFraudAlerts: req.user!.role === 'admin' ? alerts : undefined, scope }); }));
router.get('/analytics/sustainability', auth, wrap(async (_req, res) => { const rows = await Product.aggregate([{ $match: { active: true } }, { $group: { _id: null, products: { $sum: 1 }, averageCarbonKg: { $avg: '$sustainability.carbonKg' }, averageRecyclability: { $avg: '$sustainability.recyclabilityScore' }, averageRepairability: { $avg: '$sustainability.repairabilityScore' } } }]); res.json(rows[0] || { products: 0, averageCarbonKg: 0, averageRecyclability: 0, averageRepairability: 0 }); }));
router.get('/analytics/supply-chain', auth, wrap(async (_req, res) => res.json(await SupplyEvent.aggregate([{ $group: { _id: '$type', count: { $sum: 1 } } }, { $sort: { count: -1 } }]))));
router.get('/admin/fraud-alerts', auth, allow('admin'), wrap(async (_req, res) => res.json({ items: await FraudAlert.find().populate('passportId').sort({ createdAt: -1 }) })));
router.post('/admin/fraud-alerts/:id/resolve', auth, allow('admin'), wrap(async (req, res) => { const a = await FraudAlert.findByIdAndUpdate(req.params.id, { status: 'resolved', resolvedBy: req.user!.id }, { new: true }); if (!a) return res.status(404).json({ error: 'Alert not found' }); res.json(a); }));
router.get('/admin/audit-logs', auth, allow('admin'), wrap(async (req, res) => res.json({ items: await AuditLog.find().sort({ createdAt: -1 }).limit(Math.min(200, Number(req.query.limit) || 50)) })));
router.get('/users', auth, allow('admin'), wrap(async (_req, res) => res.json({ items: await User.find().select('-passwordHash').populate('organizationId') })));
router.patch('/users/:id/role', auth, allow('admin'), wrap(async (req, res) => { const role = z.enum(['admin','manufacturer','supplier','warehouse','logistics','buyer','inspector','service_center']).parse(req.body.role); const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true }).select('-passwordHash'); res.json(user); }));
router.patch('/users/:id/status', auth, allow('admin'), wrap(async (req, res) => { const user = await User.findByIdAndUpdate(req.params.id, { active: Boolean(req.body.active) }, { new: true }).select('-passwordHash'); res.json(user); }));
export default router;
