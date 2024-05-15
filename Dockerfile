FROM --platform=linux/amd64 rust

# add dependencies
RUN apt-get update && apt-get install alien softhsm opensc iputils-ping sshpass jq xxd gcc-powerpc-linux-gnu -y
RUN rustup target add powerpc-unknown-linux-gnu
RUN rustup toolchain install nightly --target powerpc-unknown-linux-gnu
RUN rustup component add rustfmt clippy

# setup luna sdk
COPY lunasdk/610-000397-010_SW_Linux_Luna_Client_V10.7.1_RevA.tar /opt
WORKDIR /opt
RUN tar xvf 610-000397-010_SW_Linux_Luna_Client_V10.7.1_RevA.tar
RUN yes | LunaClient_10.7.1-125_Linux/64/install.sh -p network -c sdk fmsdk fmtools
ENV PATH="$PATH:/usr/safenet/lunaclient/bin" LC_ALL=C
RUN configurator setValue -s Misc -e LoginAllowedOnFMEnabledHSMs -v 1