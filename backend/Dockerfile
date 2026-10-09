FROM node:20-alpine

WORKDIR /app

# Installer OpenSSL pour Prisma
RUN apk add --no-cache openssl

COPY package*.json ./

RUN npm install

COPY . .

# Générer le client Prisma
RUN npx prisma generate

EXPOSE 5000

CMD ["npm", "start"]
