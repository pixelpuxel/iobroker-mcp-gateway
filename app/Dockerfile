FROM node:22-bookworm-slim
WORKDIR /app
COPY --chown=node:node package.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY --chown=node:node src ./src
USER node
EXPOSE 8080
CMD ["npm", "start"]
