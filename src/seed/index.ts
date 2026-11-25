import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { env } from '../config/env';
import {
  Certificate,
  FraudAlert,
  Order,
  Organization,
  Passport,
  Product,
  Rfq,
  ServiceCase,
  SupplyEvent,
  User
} from '../models';

async function seed() {
  await mongoose.connect(env.mongoUri);
  const passwordHash = await bcrypt.hash('DemoPass123!', 12);
  const definitions = [
    ['Admin Demo', 'admin@demo.local', 'admin', 'Demo Platform'],
    ['Maker Demo', 'maker@demo.local', 'manufacturer', 'Acme Components'],
    ['Buyer Demo', 'buyer@demo.local', 'buyer', 'Northstar Procurement'],
    ['Supplier Demo', 'supplier@demo.local', 'supplier', 'Parts Direct'],
    ['Warehouse Demo', 'warehouse@demo.local', 'warehouse', 'Central Warehouse'],
    ['Logistics Demo', 'logistics@demo.local', 'logistics', 'Local Freight'],
    ['Inspector Demo', 'inspector@demo.local', 'inspector', 'Quality Labs'],
    ['Service Demo', 'service@demo.local', 'service_center', 'Repair Hub']
  ];
  const orgs: Record<string, any> = {};
  for (const [, , role, orgName] of definitions) {
    orgs[orgName] = await Organization.findOneAndUpdate(
      { name: orgName },
      { name: orgName, type: role, verificationStatus: 'verified' },
      { upsert: true, new: true }
    );
  }
  const users: Record<string, any> = {};
  for (const [name, email, role, orgName] of definitions) {
    users[email] = await User.findOneAndUpdate(
      { email },
      { name, email, role, passwordHash, organizationId: orgs[orgName]._id, active: true },
      { upsert: true, new: true }
    );
  }

  const maker = users['maker@demo.local'];
  const buyer = users['buyer@demo.local'];
  const inspector = users['inspector@demo.local'];
  const acmeOrg = orgs['Acme Components'];

  const productSpecs = [
    {
      sku: 'AC-CTRL-100',
      name: 'Industrial control module',
      category: 'Electronics',
      description: 'Traceable 24V DC control module for industrial automation equipment.',
      price: 12500,
      availableQuantity: 40,
      sustainability: { carbonKg: 18.4, recyclabilityScore: 78, repairabilityScore: 82 },
      specifications: { voltage: '24V DC', warranty: '24 months' }
    },
    {
      sku: 'IND-PUMP-420',
      name: 'Variable speed hydraulic pump',
      category: 'Industrial',
      description: 'High-efficiency closed-loop hydraulic pump with modular serviceable seals.',
      price: 38900,
      availableQuantity: 18,
      sustainability: { carbonKg: 42.6, recyclabilityScore: 86, repairabilityScore: 88 },
      specifications: { pressure: '250 bar', warranty: '36 months' }
    },
    {
      sku: 'AUTO-BMS-90',
      name: 'EV battery management unit',
      category: 'Automotive',
      description: 'CAN-bus BMS controller for commercial light electric fleet vehicles.',
      price: 21400,
      availableQuantity: 65,
      sustainability: { carbonKg: 14.2, recyclabilityScore: 81, repairabilityScore: 74 },
      specifications: { channels: '16S', ingress: 'IP67' }
    },
    {
      sku: 'MED-SENS-15',
      name: 'Clinical grade flow sensor',
      category: 'Medical',
      description: 'Autoclavable ultrasonic airflow sensor calibrated for respiratory devices.',
      price: 9400,
      availableQuantity: 110,
      sustainability: { carbonKg: 6.8, recyclabilityScore: 72, repairabilityScore: 69 },
      specifications: { accuracy: '±1.5%', certification: 'ISO 13485' }
    },
    {
      sku: 'EL-INV-300',
      name: 'Smart micro-grid inverter',
      category: 'Electronics',
      description: 'Three-phase industrial inverter with replaceable capacitor cartridges.',
      price: 54000,
      availableQuantity: 12,
      sustainability: { carbonKg: 35.1, recyclabilityScore: 84, repairabilityScore: 91 },
      specifications: { output: '15 kW', efficiency: '98.2%' }
    }
  ];

  const products: Record<string, any> = {};
  for (const spec of productSpecs) {
    products[spec.sku] = await Product.findOneAndUpdate(
      { sku: spec.sku },
      { ...spec, manufacturerId: acmeOrg._id, currency: 'INR', active: true },
      { upsert: true, new: true }
    );
  }

  const passportSpecs = [
    {
      publicId: 'demo-passport-ac-ctrl-0001',
      sku: 'AC-CTRL-100',
      serialNumber: 'AC-CTRL-100-0001',
      batchNumber: 'BATCH-2026-01',
      rawMaterialSources: ['Recycled aluminum frame', 'Copper winding'],
      warrantyMonths: 24,
      certTitle: 'RoHS & CE Compliance Certificate',
      certIssuer: 'Quality Labs India'
    },
    {
      publicId: 'demo-passport-ind-pump-0002',
      sku: 'IND-PUMP-420',
      serialNumber: 'IND-PUMP-420-0002',
      batchNumber: 'BATCH-2026-04',
      rawMaterialSources: ['Recycled ductile cast iron', 'Viton elastomer seals'],
      warrantyMonths: 36,
      certTitle: 'ISO 9001 Pressure Safety Report',
      certIssuer: 'Quality Labs India'
    },
    {
      publicId: 'demo-passport-auto-bms-0003',
      sku: 'AUTO-BMS-90',
      serialNumber: 'AUTO-BMS-90-0003',
      batchNumber: 'BATCH-2026-07',
      rawMaterialSources: ['Lead-free FR4 PCB', 'Recycled ABS housing'],
      warrantyMonths: 24,
      certTitle: 'AIS-156 Automotive EMC Clearance',
      certIssuer: 'Quality Labs India'
    },
    {
      publicId: 'demo-passport-med-sens-0004',
      sku: 'MED-SENS-15',
      serialNumber: 'MED-SENS-15-0004',
      batchNumber: 'BATCH-2026-09',
      rawMaterialSources: ['Medical-grade PEEK polymer', '316L stainless steel'],
      warrantyMonths: 18,
      certTitle: 'ISO 13485 Biocompatibility Audit',
      certIssuer: 'Quality Labs India'
    }
  ];

  const passports: Record<string, any> = {};
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;

  for (const spec of passportSpecs) {
    const product = products[spec.sku];
    let passport: any = await Passport.findOne({ serialNumber: spec.serialNumber });
    if (!passport) {
      passport = await Passport.create({
        publicId: spec.publicId,
        productId: product._id,
        serialNumber: spec.serialNumber,
        batchNumber: spec.batchNumber,
        rawMaterialSources: spec.rawMaterialSources,
        warranty: { durationMonths: spec.warrantyMonths, startsAt: new Date(now - 20 * dayMs) },
        sustainability: product.sustainability,
        createdBy: maker._id,
        lastModifiedBy: maker._id
      });
    }
    passports[spec.sku] = passport;

    if (!(await SupplyEvent.exists({ passportId: passport._id }))) {
      await SupplyEvent.insertMany([
        {
          passportId: passport._id,
          type: 'manufacturing',
          actorId: maker._id,
          organizationId: acmeOrg._id,
          location: 'Pune Plant 2',
          notes: `Manufactured and issued passport (${spec.batchNumber})`,
          occurredAt: new Date(now - 14 * dayMs)
        },
        {
          passportId: passport._id,
          type: 'inspection',
          actorId: inspector._id,
          organizationId: orgs['Quality Labs']._id,
          location: 'Pune QA Lab',
          notes: 'Passed bench calibration and material compliance check',
          occurredAt: new Date(now - 11 * dayMs)
        },
        {
          passportId: passport._id,
          type: 'warehouse',
          actorId: users['warehouse@demo.local']._id,
          organizationId: orgs['Central Warehouse']._id,
          location: 'Bhiwandi Hub',
          notes: 'Received into temperature-controlled inventory',
          occurredAt: new Date(now - 7 * dayMs)
        },
        {
          passportId: passport._id,
          type: 'logistics',
          actorId: users['logistics@demo.local']._id,
          organizationId: orgs['Local Freight']._id,
          location: 'NH-48 Corridor',
          notes: 'Dispatched via verified regional carrier',
          occurredAt: new Date(now - 3 * dayMs)
        }
      ]);
    }

    if (!(await Certificate.exists({ passportId: passport._id }))) {
      await Certificate.create({
        passportId: passport._id,
        title: spec.certTitle,
        issuer: spec.certIssuer,
        issuedAt: new Date(now - 30 * dayMs),
        expiresAt: new Date(now + 335 * dayMs),
        status: 'valid',
        uploadedBy: inspector._id
      });
    }
  }

  if (!(await Order.exists({ buyerId: buyer._id }))) {
    await Order.insertMany([
      {
        buyerId: buyer._id,
        sellerId: acmeOrg._id,
        productId: products['AC-CTRL-100']._id,
        passportId: passports['AC-CTRL-100']._id,
        quantity: 6,
        unitPrice: 12500,
        total: 75000,
        status: 'delivered',
        createdAt: new Date(now - 12 * dayMs)
      },
      {
        buyerId: buyer._id,
        sellerId: acmeOrg._id,
        productId: products['IND-PUMP-420']._id,
        passportId: passports['IND-PUMP-420']._id,
        quantity: 2,
        unitPrice: 38900,
        total: 77800,
        status: 'shipped',
        createdAt: new Date(now - 5 * dayMs)
      },
      {
        buyerId: buyer._id,
        sellerId: acmeOrg._id,
        productId: products['AUTO-BMS-90']._id,
        passportId: passports['AUTO-BMS-90']._id,
        quantity: 10,
        unitPrice: 21400,
        total: 214000,
        status: 'confirmed',
        createdAt: new Date(now - 2 * dayMs)
      },
      {
        buyerId: buyer._id,
        sellerId: acmeOrg._id,
        productId: products['MED-SENS-15']._id,
        passportId: passports['MED-SENS-15']._id,
        quantity: 15,
        unitPrice: 9400,
        total: 141000,
        status: 'placed',
        createdAt: new Date(now - 1 * dayMs)
      }
    ]);
  }

  if (!(await Rfq.exists({ buyerId: buyer._id }))) {
    await Rfq.insertMany([
      {
        buyerId: buyer._id,
        productId: products['EL-INV-300']._id,
        quantity: 8,
        message: 'Need staggered delivery across Q1 with full batch passports.',
        status: 'quoted',
        quote: {
          amount: 412000,
          currency: 'INR',
          message: 'Includes volume discount and 36-month extended warranty.',
          sellerId: acmeOrg._id,
          validUntil: new Date(now + 14 * dayMs)
        }
      },
      {
        buyerId: buyer._id,
        productId: products['AC-CTRL-100']._id,
        quantity: 50,
        message: 'Annual maintenance stock replenishment quote request.',
        status: 'open'
      }
    ]);
  }

  if (!(await ServiceCase.exists({ ownerId: buyer._id }))) {
    await ServiceCase.create({
      passportId: passports['AC-CTRL-100']._id,
      ownerId: buyer._id,
      type: 'warranty',
      description: 'Routine firmware verification under 24-month warranty.',
      status: 'resolved',
      resolution: 'Diagnostic passed; firmware updated to v2.4.'
    });
  }

  if (!(await FraudAlert.exists({ serialNumber: 'AC-CTRL-100-0001' }))) {
    await FraudAlert.create({
      type: 'duplicate_serial',
      message: 'Duplicate serial AC-CTRL-100-0001 was flagged during simulated test check',
      passportId: passports['AC-CTRL-100']._id,
      serialNumber: 'AC-CTRL-100-0001',
      status: 'open'
    });
  }

  console.log('Seed complete. Demo password: DemoPass123!');
  await mongoose.disconnect();
}

seed().catch(async (error) => {
  console.error(error);
  await mongoose.disconnect();
  process.exit(1);
});
