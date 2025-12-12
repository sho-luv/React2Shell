FROM nginx:alpine

# Copy the logging dashboard
COPY index.html /usr/share/nginx/html/index.html
COPY style.css /usr/share/nginx/html/style.css
COPY app.js /usr/share/nginx/html/app.js

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
