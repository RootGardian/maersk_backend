import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import http from 'http';
import { Server } from 'socket.io';
import helmet from 'helmet';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 5000;
const PEPPER = process.env.PEPPER;
const JWT_SECRET = process.env.JWT_SECRET;

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
});

app.set('io', io);

io.on('connection', (socket) => {
  console.log('Utilisateur connecté Socket.io:', socket.id);

  socket.on('join', (userId) => {
    if (userId) {
      socket.join(userId.toString());
      console.log(`Utilisateur ${userId} a rejoint sa room.`);
    }
  });

  socket.on('disconnect', () => {
    console.log('Utilisateur déconnecté:', socket.id);
  });
});

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Accès refusé. Jeton manquant.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Jeton invalide ou expiré.' });
    req.user = user;
    next();
  });
};


// Auto Seed Utilisateur Admin: Marie Josephine Gomez
async function seedAdminUser() {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@maersk.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';

    const existingAdmin = await prisma.user.findFirst({
      where: { email: adminEmail }
    });

    if (!existingAdmin) {
      const passwordHash = await bcrypt.hash(adminPassword + PEPPER, 10);
      await prisma.user.create({
        data: {
          firstName: 'Marie Josephine',
          lastName: 'Gomez',
          email: adminEmail,
          passwordHash: passwordHash,
          role: 'ADMIN',
          isActive: true
        }
      });
      console.log(` Compte ADMIN créé avec succès`);
    } else if (existingAdmin.role !== 'ADMIN') {
      await prisma.user.update({
        where: { id: existingAdmin.id },
        data: { role: 'ADMIN' }
      });
    }
  } catch (err) {
    console.error('Info Seed Admin:', err.message);
  }
}
seedAdminUser();

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Backend Express & PostgreSQL Maersk opérationnel', timestamp: new Date() });
});

app.use((req, res, next) => {
  const openRoutes = ['/api/auth/login', '/api/health'];
  if (openRoutes.includes(req.path) || req.path.startsWith('/socket.io/')) {
    return next();
  }
  return authenticateToken(req, res, next);
});

// Auth Login Route
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Veuillez saisir votre email et votre mot de passe.' });
  }

  try {
    const cleanEmail = email.trim().toLowerCase();
    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: cleanEmail },
          { email: { equals: cleanEmail, mode: 'insensitive' } }
        ]
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'Utilisateur non trouvé avec cet email.' });
    }

    if (!user.isActive) {
      return res.status(403).json({ error: 'Votre compte est désactivé. Veuillez contacter un administrateur.' });
    }

    const isPasswordValid = await bcrypt.compare(password + PEPPER, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Mot de passe incorrect.' });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() }
    });

    const jwtToken = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '8h' });

    res.json({
      message: 'Connexion réussie',
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role
      },
      token: jwtToken
    });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la connexion', details: error.message });
  }
});

// Users Route (GET, POST, PATCH)
app.get('/api/users', async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, firstName: true, lastName: true, email: true, role: true, isActive: true, createdAt: true, lastLogin: true },
      orderBy: { createdAt: 'desc' }
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération des utilisateurs', details: error.message });
  }
});

app.post('/api/users', async (req, res) => {
  const { firstName, lastName, email, password, role } = req.body;
  try {
    const plainPwd = password || 'maersk2026';
    const passwordHash = await bcrypt.hash(plainPwd + PEPPER, 10);
    const newUser = await prisma.user.create({
      data: {
        firstName,
        lastName,
        email: email.trim().toLowerCase(),
        passwordHash,
        role: role || 'ACCOUNTANT',
        isActive: true
      }
    });
    res.status(201).json(newUser);
  } catch (error) {
    res.status(400).json({ error: 'Impossible de créer l\'utilisateur', details: error.message });
  }
});

app.patch('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  const { role, isActive, password } = req.body;
  try {
    const dataToUpdate = {
      ...(role !== undefined && { role }),
      ...(isActive !== undefined && { isActive })
    };
    if (password !== undefined) {
      dataToUpdate.passwordHash = await bcrypt.hash(password + PEPPER, 10);
    }
    const updated = await prisma.user.update({
      where: { id: parseInt(id) },
      data: dataToUpdate
    });
    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: 'Erreur lors de la mise à jour de l\'utilisateur', details: error.message });
  }
});

// Companies Route (GET, POST, PATCH)
app.get('/api/companies', async (req, res) => {
  try {
    const companies = await prisma.company.findMany({ orderBy: { id: 'desc' } });
    res.json(companies);
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération des compagnies', details: error.message });
  }
});

app.post('/api/companies', async (req, res) => {
  const { name, address, contact, telephone, service } = req.body;
  try {
    const comp = await prisma.company.create({ data: { name, address, contact, telephone, service } });
    res.status(201).json(comp);
  } catch (error) {
    res.status(400).json({ error: 'Erreur lors de la création de la compagnie', details: error.message });
  }
});

app.patch('/api/companies/:id', async (req, res) => {
  const { id } = req.params;
  const { name, address, contact, telephone, service } = req.body;
  try {
    const comp = await prisma.company.update({
      where: { id: parseInt(id) },
      data: {
        ...(name !== undefined && name !== '' && { name }),
        ...(address !== undefined && address !== '' && { address }),
        ...(contact !== undefined && contact !== '' && { contact }),
        ...(telephone !== undefined && telephone !== '' && { telephone }),
        ...(service !== undefined && service !== '' && { service }),
      }
    });
    res.json(comp);
  } catch (error) {
    res.status(400).json({ error: 'Erreur lors de la mise à jour de la compagnie', details: error.message });
  }
});

// Vendors Route (GET, POST, PATCH)
app.get('/api/vendors', async (req, res) => {
  try {
    const vendors = await prisma.vendor.findMany({ orderBy: { id: 'desc' } });
    res.json(vendors);
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération des fournisseurs', details: error.message });
  }
});

app.post('/api/vendors', async (req, res) => {
  const { name, address, contactPerson, telephone, email, sector } = req.body;
  try {
    const vend = await prisma.vendor.create({ data: { name, address, contactPerson, telephone, email, sector } });
    res.status(201).json(vend);
  } catch (error) {
    res.status(400).json({ error: 'Erreur lors de la création du fournisseur', details: error.message });
  }
});

app.patch('/api/vendors/:id', async (req, res) => {
  const { id } = req.params;
  const { name, address, contactPerson, telephone, email, sector } = req.body;
  try {
    const vend = await prisma.vendor.update({
      where: { id: parseInt(id) },
      data: {
        ...(name !== undefined && name !== '' && { name }),
        ...(address !== undefined && address !== '' && { address }),
        ...(contactPerson !== undefined && contactPerson !== '' && { contactPerson }),
        ...(telephone !== undefined && telephone !== '' && { telephone }),
        ...(email !== undefined && email !== '' && { email }),
        ...(sector !== undefined && sector !== '' && { sector }),
      }
    });
    res.json(vend);
  } catch (error) {
    res.status(400).json({ error: 'Erreur lors de la mise à jour du fournisseur', details: error.message });
  }
});

// Articles Route (GET, POST, PATCH)
app.get('/api/articles', async (req, res) => {
  try {
    const articles = await prisma.article.findMany({ orderBy: { id: 'desc' } });
    res.json(articles);
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération des articles', details: error.message });
  }
});

app.post('/api/articles', async (req, res) => {
  const { name, description, unitPrice } = req.body;
  try {
    const art = await prisma.article.create({ data: { name, description, unitPrice: parseFloat(unitPrice || 0) } });
    res.status(201).json(art);
  } catch (error) {
    res.status(400).json({ error: 'Erreur lors de la création de l\'article', details: error.message });
  }
});

app.patch('/api/articles/:id', async (req, res) => {
  const { id } = req.params;
  const { name, description, unitPrice } = req.body;
  try {
    const art = await prisma.article.update({
      where: { id: parseInt(id) },
      data: {
        ...(name !== undefined && name !== '' && { name }),
        ...(description !== undefined && description !== '' && { description }),
        ...(unitPrice !== undefined && unitPrice !== '' && { unitPrice: parseFloat(unitPrice) }),
      }
    });
    res.json(art);
  } catch (error) {
    res.status(400).json({ error: 'Erreur lors de la mise à jour de l\'article', details: error.message });
  }
});

// Purchase Requests GET & POST
app.get('/api/purchase-requests', async (req, res) => {
  try {
    const requests = await prisma.purchaseRequest.findMany({
      include: {
        company: true,
        vendor: true,
        requestedBy: { select: { id: true, firstName: true, lastName: true, email: true, signature: true } },
        approvedBy: { select: { id: true, firstName: true, lastName: true, email: true, signature: true } },
        items: true,
      },
      orderBy: { createdAt: 'desc' }
    });
    res.json(requests);
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération des demandes d\'achat', details: error.message });
  }
});

app.post('/api/purchase-requests', async (req, res) => {
  const {
    requestNo,
    requestDate,
    companyId,
    vendorId,
    companyName,
    vendorName,
    quoteNumber,
    paymentTerms,
    deliveryDate,
    sector,
    currency,
    subtotal,
    tax,
    labourCost,
    total,
    instructions,
    requestedByUserId,
    status,
    items
  } = req.body;

  try {
    // 1. Ensure valid companyId
    let finalCompanyId = companyId ? parseInt(companyId) : null;
    if (!finalCompanyId || isNaN(finalCompanyId)) {
      const targetCompName = companyName || 'Maersk Guinea SA';
      let comp = await prisma.company.findFirst({
        where: { name: { equals: targetCompName, mode: 'insensitive' } }
      });
      if (!comp) {
        comp = await prisma.company.create({ data: { name: targetCompName } });
      }
      finalCompanyId = comp.id;
    }

    // 2. Ensure valid vendorId
    let finalVendorId = vendorId ? parseInt(vendorId) : null;
    if (!finalVendorId || isNaN(finalVendorId)) {
      const targetVendName = vendorName || 'Fournisseur Général';
      let vend = await prisma.vendor.findFirst({
        where: { name: { equals: targetVendName, mode: 'insensitive' } }
      });
      if (!vend) {
        vend = await prisma.vendor.create({ data: { name: targetVendName } });
      }
      finalVendorId = vend.id;
    }

    // 3. Ensure valid requestedByUserId
    let finalUserId = requestedByUserId ? parseInt(requestedByUserId) : null;
    if (!finalUserId || isNaN(finalUserId)) {
      const firstUser = await prisma.user.findFirst();
      finalUserId = firstUser ? firstUser.id : 1;
    }

    const newRequest = await prisma.purchaseRequest.create({
      data: {
        requestNo: requestNo || `PO-${Date.now().toString().slice(-6)}`,
        requestDate: requestDate ? new Date(requestDate) : new Date(),
        companyId: finalCompanyId,
        vendorId: finalVendorId,
        quoteNumber: quoteNumber || '',
        paymentTerms: paymentTerms || '',
        deliveryDate: deliveryDate ? new Date(deliveryDate) : null,
        sector: sector || '',
        currency: currency || 'GNF',
        subtotal: parseFloat(subtotal || 0),
        tax: parseFloat(tax || 0),
        labourCost: parseFloat(labourCost || 0),
        total: parseFloat(total || 0),
        instructions: instructions || '',
        requestedByUserId: finalUserId,
        ...(req.body.approvedByUserId ? { approvedByUserId: parseInt(req.body.approvedByUserId) } : {}),
        status: status || 'PENDING',
        items: {
          create: items ? items.map((item) => ({
            articleId: item.articleId ? parseInt(item.articleId) : null,
            articleName: item.articleName || 'Article',
            description: item.description || '',
            quantity: parseFloat(item.quantity || 1),
            unitPrice: parseFloat(item.unitPrice || 0),
            total: parseFloat(item.total || 0),
          })) : []
        }
      },
      include: {
        company: true,
        vendor: true,
        items: true
      }
    });

    if (newRequest.status === 'PENDING' && newRequest.approvedByUserId) {
      const io = req.app.get('io');
      io.to(newRequest.approvedByUserId.toString()).emit('new_request', newRequest);
    }

    res.status(201).json(newRequest);
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'Ce numéro de commande existe déjà.', details: error.message });
    }
    console.error('Erreur création PurchaseRequest:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la demande d\'achat', details: error.message });
  }
});

// Update PurchaseRequest (ex: Convertir brouillon en validation ou modifier)
app.patch('/api/purchase-requests/:id', async (req, res) => {
  const { id } = req.params;
  const { status, companyId, vendorId, quoteNumber, paymentTerms, deliveryDate, currency, subtotal, tax, labourCost, total, instructions, items } = req.body;

  try {
    const updateData = {};
    if (status) updateData.status = status;
    if (req.body.approvedByUserId !== undefined) updateData.approvedByUserId = parseInt(req.body.approvedByUserId);
    if (companyId) updateData.companyId = parseInt(companyId);
    if (vendorId) updateData.vendorId = parseInt(vendorId);
    if (quoteNumber !== undefined) updateData.quoteNumber = quoteNumber;
    if (paymentTerms !== undefined) updateData.paymentTerms = paymentTerms;
    if (deliveryDate !== undefined) updateData.deliveryDate = deliveryDate ? new Date(deliveryDate) : null;
    if (currency) updateData.currency = currency;
    if (subtotal !== undefined) updateData.subtotal = parseFloat(subtotal || 0);
    if (tax !== undefined) updateData.tax = parseFloat(tax || 0);
    if (labourCost !== undefined) updateData.labourCost = parseFloat(labourCost || 0);
    if (total !== undefined) updateData.total = parseFloat(total || 0);
    if (instructions !== undefined) updateData.instructions = instructions;

    if (items && Array.isArray(items)) {
      await prisma.purchaseRequestItem.deleteMany({ where: { requestId: parseInt(id) } });
      updateData.items = {
        create: items.map((item) => ({
          articleId: item.articleId ? parseInt(item.articleId) : null,
          articleName: item.articleName || 'Article',
          description: item.description || '',
          quantity: parseFloat(item.quantity || 1),
          unitPrice: parseFloat(item.unitPrice || 0),
          total: parseFloat(item.total || 0),
        }))
      };
    }

    const updated = await prisma.purchaseRequest.update({
      where: { id: parseInt(id) },
      data: updateData,
      include: { company: true, vendor: true, items: true }
    });

    // Handle real-time notifications
    const io = req.app.get('io');
    if (status === 'PENDING' && updated.approvedByUserId) {
      // Sent to approver
      io.to(updated.approvedByUserId.toString()).emit('new_request', updated);
    } else if (status === 'APPROVED' || status === 'REJECTED') {
      // Sent back to creator
      if (updated.requestedByUserId) {
        io.to(updated.requestedByUserId.toString()).emit('request_updated', updated);
      }
    }

    res.json(updated);
  } catch (error) {
    console.error('Erreur mise à jour PurchaseRequest:', error);
    res.status(400).json({ error: 'Erreur lors de la mise à jour de la demande', details: error.message });
  }
});

// Delete PurchaseRequest (Supprimer un brouillon)
app.delete('/api/purchase-requests/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await prisma.purchaseRequestItem.deleteMany({ where: { requestId: parseInt(id) } });
    await prisma.purchaseRequest.delete({ where: { id: parseInt(id) } });
    res.json({ success: true, message: 'Commande supprimée avec succès' });
  } catch (error) {
    console.error('Erreur suppression PurchaseRequest:', error);
    res.status(400).json({ error: 'Erreur lors de la suppression', details: error.message });
  }
});

// Bulk Import Routes for fast high-performance Excel imports
app.post('/api/bulk-import/companies', async (req, res) => {
  const { items } = req.body;
  if (!Array.isArray(items)) return res.status(400).json({ error: 'Format d\'envoi invalide (tableau attendu)' });

  let createdCount = 0;
  let updatedCount = 0;

  try {
    for (const item of items) {
      if (!item.name || !item.name.trim()) continue;
      const normalizedName = item.name.trim().toLowerCase();
      const existing = await prisma.company.findFirst({
        where: { name: { equals: normalizedName, mode: 'insensitive' } }
      });

      if (existing) {
        await prisma.company.update({
          where: { id: existing.id },
          data: {
            ...(item.address && { address: item.address }),
            ...(item.contact && { contact: item.contact }),
            ...(item.telephone && { telephone: item.telephone }),
            ...(item.service && { service: item.service }),
          }
        });
        updatedCount++;
      } else {
        await prisma.company.create({
          data: {
            name: item.name.trim(),
            address: item.address || '',
            contact: item.contact || '',
            telephone: item.telephone || '',
            service: item.service || ''
          }
        });
        createdCount++;
      }
    }
    res.json({ success: true, createdCount, updatedCount });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de l\'importation en masse des compagnies', details: error.message });
  }
});

app.post('/api/bulk-import/vendors', async (req, res) => {
  const { items } = req.body;
  if (!Array.isArray(items)) return res.status(400).json({ error: 'Format d\'envoi invalide (tableau attendu)' });

  let createdCount = 0;
  let updatedCount = 0;

  try {
    for (const item of items) {
      if (!item.name || !item.name.trim()) continue;
      const normalizedName = item.name.trim().toLowerCase();
      const existing = await prisma.vendor.findFirst({
        where: { name: { equals: normalizedName, mode: 'insensitive' } }
      });

      if (existing) {
        await prisma.vendor.update({
          where: { id: existing.id },
          data: {
            ...(item.address && { address: item.address }),
            ...(item.contactPerson && { contactPerson: item.contactPerson }),
            ...(item.telephone && { telephone: item.telephone }),
            ...(item.email && { email: item.email }),
            ...(item.sector && { sector: item.sector }),
          }
        });
        updatedCount++;
      } else {
        await prisma.vendor.create({
          data: {
            name: item.name.trim(),
            address: item.address || '',
            contactPerson: item.contactPerson || '',
            telephone: item.telephone || '',
            email: item.email || '',
            sector: item.sector || ''
          }
        });
        createdCount++;
      }
    }
    res.json({ success: true, createdCount, updatedCount });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de l\'importation en masse des fournisseurs', details: error.message });
  }
});

app.post('/api/bulk-import/articles', async (req, res) => {
  const { items } = req.body;
  if (!Array.isArray(items)) return res.status(400).json({ error: 'Format d\'envoi invalide (tableau attendu)' });

  let createdCount = 0;
  let updatedCount = 0;

  try {
    for (const item of items) {
      if (!item.name || !item.name.trim()) continue;
      const normalizedName = item.name.trim().toLowerCase();
      const existing = await prisma.article.findFirst({
        where: { name: { equals: normalizedName, mode: 'insensitive' } }
      });

      if (existing) {
        await prisma.article.update({
          where: { id: existing.id },
          data: {
            ...(item.description && { description: item.description }),
            ...(item.unitPrice !== undefined && { unitPrice: parseFloat(item.unitPrice || 0) }),
          }
        });
        updatedCount++;
      } else {
        await prisma.article.create({
          data: {
            name: item.name.trim(),
            description: item.description || '',
            unitPrice: parseFloat(item.unitPrice || 0)
          }
        });
        createdCount++;
      }
    }
    res.json({ success: true, createdCount, updatedCount });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de l\'importation en masse des articles', details: error.message });
  }
});

app.post('/api/bulk-import/purchase-requests', async (req, res) => {
  const { items } = req.body;
  if (!Array.isArray(items)) return res.status(400).json({ error: 'Format d\'envoi invalide (tableau attendu)' });

  let createdCount = 0;
  let skippedCount = 0;

  try {
    const existingRequests = await prisma.purchaseRequest.findMany({ select: { requestNo: true } });
    const existingNos = new Set(existingRequests.map(r => r.requestNo.toLowerCase()));

    const allCompanies = await prisma.company.findMany();
    const allVendors = await prisma.vendor.findMany();
    const firstUser = await prisma.user.findFirst();
    const defaultUserId = firstUser ? firstUser.id : 1;

    for (const orderData of items) {
      const orderNo = orderData.requestNo;
      if (!orderNo || existingNos.has(orderNo.toLowerCase())) {
        skippedCount++;
        continue;
      }

      let matchedComp = allCompanies.find(c => c.name.toLowerCase() === (orderData.companyName || '').toLowerCase());
      if (!matchedComp && orderData.companyName) {
        matchedComp = await prisma.company.create({ data: { name: orderData.companyName } });
        allCompanies.push(matchedComp);
      }

      let matchedVend = allVendors.find(v => v.name.toLowerCase() === (orderData.vendorName || '').toLowerCase());
      if (!matchedVend && orderData.vendorName) {
        matchedVend = await prisma.vendor.create({ data: { name: orderData.vendorName } });
        allVendors.push(matchedVend);
      }

      await prisma.purchaseRequest.create({
        data: {
          requestNo: orderNo,
          requestDate: orderData.requestDate ? new Date(orderData.requestDate) : new Date(),
          companyId: matchedComp ? matchedComp.id : null,
          vendorId: matchedVend ? matchedVend.id : null,
          quoteNumber: orderData.quoteNumber || '',
          paymentTerms: orderData.paymentTerms || '30 jours',
          currency: orderData.currency || 'GNF',
          subtotal: parseFloat(orderData.subtotal || 0),
          tax: parseFloat(orderData.tax || 0),
          labourCost: parseFloat(orderData.labourCost || 0),
          total: parseFloat(orderData.total || 0),
          instructions: orderData.instructions || '',
          requestedByUserId: orderData.requestedById || defaultUserId,
          status: orderData.status || 'APPROVED',
          items: {
            create: (orderData.items || []).map(item => ({
              articleName: item.articleName || 'Article',
              description: item.description || '',
              quantity: parseFloat(item.quantity || 1),
              unitPrice: parseFloat(item.unitPrice || 0),
              total: parseFloat(item.total || 0),
            }))
          }
        }
      });
      existingNos.add(orderNo.toLowerCase());
      createdCount++;
    }

    res.json({ success: true, createdCount, skippedCount });
  } catch (error) {
    console.error('Erreur bulk import POs:', error);
    res.status(500).json({ error: 'Erreur lors de l\'importation en masse des bons de commande', details: error.message });
  }
});

// Update user signature
app.patch('/api/users/:id/signature', async (req, res) => {
  const { id } = req.params;
  const { signature } = req.body;
  try {
    const updated = await prisma.user.update({
      where: { id: parseInt(id) },
      data: { signature }
    });
    res.json({ success: true, message: 'Signature mise à jour', user: updated });
  } catch (error) {
    res.status(400).json({ error: 'Erreur mise à jour signature' });
  }
});

server.listen(PORT, () => {
  console.log(`🚀 Serveur backend Maersk démarré sur http://localhost:${PORT}`);
});
