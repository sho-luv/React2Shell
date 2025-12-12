FROM owasp/modsecurity-crs:nginx-alpine

# Custom ModSecurity rules for RSC exploit detection
COPY modsecurity-rules.conf /etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-RSC-EXPLOIT.conf
COPY --chmod=644 nginx.conf /etc/nginx/templates/conf.d/default.conf.template

ENV BACKEND=http://vulnerable:3000
ENV PORT=8080

EXPOSE 8080
