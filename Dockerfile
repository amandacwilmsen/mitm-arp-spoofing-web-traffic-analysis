
# A aplicação utiliza sockets AF_PACKET, disponíveis no Linux.
FROM python:3.12-slim

# Ferramentas básicas para observar IPs, rotas e testar conectividade.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
CMD ["sleep", "infinity"]
