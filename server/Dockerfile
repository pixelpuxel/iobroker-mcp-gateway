FROM node:22-alpine
WORKDIR /app
COPY --chown=node:node package*.json ./
RUN npm install --omit=dev
COPY --chown=node:node server.js ./
USER node
EXPOSE 8090
CMD ["node", "server.js"]
