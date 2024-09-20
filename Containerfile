FROM registry.access.redhat.com/ubi9/ubi:latest

ARG RUST_VERSION="1.80.1"

RUN dnf install -y gcc openssl openssl-devel cmake gcc-c++ git curl-minimal

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION}

ENV PATH "$PATH:/root/.cargo/bin"

RUN mkdir /usr/src/project

COPY . /usr/src/project

WORKDIR /usr/src/project

RUN cargo build --release

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

LABEL com.redhat.component ="Trustify"
LABEL description ="Trustify"
LABEL io.k8s.description ="Trustify"
LABEL io.k8s.display-name ="Trustif"
LABEL io.openshift.tags ="Trustify"
LABEL name ="Trustify"
LABEL org.opencontainers.image.source="https://github.com/trustification/rhtpa"
LABEL summary ="Trustify"

RUN microdnf reinstall tzdata -y
ENV TZ=UTC
RUN mkdir trustify

COPY --from=0 /usr/src/project/target/release/trustd trustify
COPY --from=0 /usr/src/project/run-integration-test.sh trustify

RUN useradd -ms /bin/bash trustify

RUN chown trustify -R trustify

RUN mkdir /licenses

COPY ./LICENSE /licenses/AL

USER trustify

WORKDIR trustify
