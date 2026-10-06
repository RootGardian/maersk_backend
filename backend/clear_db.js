import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('Suppression en cours...');
  await prisma.purchaseRequestItem.deleteMany({});
  await prisma.purchaseRequest.deleteMany({});
  await prisma.article.deleteMany({});
  await prisma.vendor.deleteMany({});
  await prisma.company.deleteMany({});
  await prisma.user.deleteMany({});
  console.log('SUCCÈS: Toutes les tables ont été réinitialisées.');
}

main()
  .catch((err) => {
    console.error('Erreur lors du vidage des tables:', err);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
