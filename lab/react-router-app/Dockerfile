FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies (will show security warning for react-server-dom-webpack)
RUN npm install

# Copy server file
COPY server.js ./

# Create flag
RUN echo "FLAG{react_router_rsc_pwn3d_2025}" > /app/flag.txt
RUN chmod 644 /app/flag.txt

# Expose port
EXPOSE 3000

# Start with --conditions react-server for server module access
CMD ["npm", "start"]
