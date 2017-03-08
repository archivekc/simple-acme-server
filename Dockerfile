FROM alpine:latest

COPY simple-acme-server /bin/simple-acme-server

CMD /bin/simple-acme-server
