FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    openssh-server \
    openssh-client \
    libssl-dev \
    libkrb5-dev \
    libcurl4-openssl-dev \
    libjson-c-dev \
    pkg-config \
    wget \
    vim

# Set root password for SSH login (for testing purposes only)
RUN echo 'root:password' | chpasswd

RUN mkdir /var/run/sshd
RUN ssh-keygen -A

EXPOSE 22

COPY ./gssapi_mech /usr/local/src/gssapi_mech

# Build and install your GSSAPI mechanism
WORKDIR /usr/local/src/gssapi_mech
RUN make install

COPY ./sshd_config /etc/ssh/sshd_config
COPY ./ssh_config /etc/ssh/config

# Start SSHD
CMD ["/usr/sbin/sshd", "-D"]

