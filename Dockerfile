FROM python:3.13-alpine

RUN adduser -D -H -u 10138 btnetplay

COPY server.py /usr/local/bin/btnetplay-server

RUN chmod 0755 /usr/local/bin/btnetplay-server

USER btnetplay

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "/usr/local/bin/btnetplay-server"]
