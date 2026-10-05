# Benchmark runtime. Every product runs inside the same image, as the same
# unprivileged user, with the same JDK. Pinned by digest in RUNTIME.lock after build.
# Java 25 is the newest LTS and the only JDK every product under test loads on
# (FoxGate 1.2.0-pre10 is compiled for class file 69). JDK 21 runs as a separate
# compatibility row: docker build --build-arg JDK=21.
ARG JDK=25
FROM eclipse-temurin:${JDK}-jdk-noble

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-cryptography python3-yaml python3-h2 iptables redis-server procps \
      ca-certificates dnsutils curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1001 --create-home --shell /usr/sbin/nologin mc

# The orchestrator, interposer and client run as root; product JVMs run as `mc`.
WORKDIR /bench
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "-m", "bench"]
