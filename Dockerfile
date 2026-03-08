FROM node:22-slim

WORKDIR /app

RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

COPY package.json .
RUN npm install

COPY . .

RUN mkdir -p .well-known public/vc status-data logs

EXPOSE 3100

ENV SECRET_KEY=""
ENV ORG_DID=""
ENV REGISTRY_URL="http://localhost:8001"
ENV SIGNING_MODE="local"
ENV PORT=3100

CMD ["node", "server.js"]
