FROM nginx:1.27-alpine

COPY index.html /usr/share/nginx/html/
COPY css/ /usr/share/nginx/html/css/
COPY js/ /usr/share/nginx/html/js/
COPY vendor/ /usr/share/nginx/html/vendor/

RUN adduser -D -H -u 1001 firegen && \
    chown -R firegen:firegen /usr/share/nginx/html && \
    chown -R firegen:firegen /var/cache/nginx && \
    chown -R firegen:firegen /var/log/nginx && \
    touch /var/run/nginx.pid && \
    chown firegen:firegen /var/run/nginx.pid

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost/ || exit 1
