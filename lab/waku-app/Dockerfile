FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies
RUN npm install

# Copy source
COPY src ./src

# Create flag
RUN echo "FLAG{waku_rsc_pwn3d_2025}" > /app/flag.txt
RUN chmod 644 /app/flag.txt

# Build
RUN npm run build

# Expose port (Waku defaults to 8080)
EXPOSE 8080

# Start
CMD ["npm", "start"]
