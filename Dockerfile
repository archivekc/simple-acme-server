FROM alpine:latest

COPY simple-acme-server /bin/simple-acme-server
COPY *.html /
RUN chmod 777 /bin/simple-acme-server
RUN mkdir /keys
RUN chmod 700 /keys
WORKDIR /
VOLUME /keys

CMD /bin/simple-acme-server
