FROM ubuntu:latest
SHELL ["/bin/bash", "-c"]

RUN apt-get update

RUN <<EOT
    apt-get install -y software-properties-common
    add-apt-repository ppa:deadsnakes/ppa
    apt-get update
    apt-get install -y \
        python3.10 \
        python3.10-venv \
        python3.10-dev
EOT

# TODO Remove the commented packages
RUN apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-setuptools \
    # libboost-dev \
    # libgmp-dev \
    # clang-14 \
    # llvm-14 \
    # cmake \
    git \
    wget \
    # pkg-config \
    # ninja-build \
    gcc-arm-none-eabi \
    sudo \
    neovim

WORKDIR /home/ubuntu

RUN python3.10 -m venv venv

RUN venv/bin/pip install \
    -U pip \
    setuptools \
    importlib-resources

# Install Radare2
RUN <<EOT
    set -e
    git clone https://github.com/radareorg/radare2
    cd radare2
    ./sys/install.sh
    set +e
EOT

# Inside psca
COPY . psca

RUN venv/bin/pip install -r psca/requirements.txt

# Download optimathsat
RUN <<EOT
    set -e
    [ -d psca/omt ] || mkdir psca/omt
    cd psca/omt
    version="1.7.3"
    linux="optimathsat-${version}-linux-64-bit.tar.gz"
    wget "https://optimathsat.disi.unitn.it/releases/optimathsat-${version}/${linux}"
    tar -xzf ${linux}
    macos="optimathsat-${version}-macos-64-bit.tar.gz"
    wget "https://optimathsat.disi.unitn.it/releases/optimathsat-${version}/${macos}"
    tar -xzf ${macos}
    set +e
EOT

RUN <<EOT
    PYZ3DIR=$(venv/bin/python -c 'import z3; print(z3.__path__[0])')
    echo "export LD_LIBRARY_PATH=\"${PYZ3DIR}/lib\"" >> venv/bin/activate
    echo 'export PYTHONPATH="${HOME}/psca/modules/pascal:${HOME}/psca/modules/bv_mc"' >> venv/bin/activate
    echo 'source ${HOME}/venv/bin/activate' >> .bashrc
    cp psca/src/radare2/.radare2rc .
    chown -R ubuntu:ubuntu /home/ubuntu
EOT

RUN usermod -s /bin/bash -p "$(openssl passwd -1 root)" root
RUN usermod -s /bin/bash -p "$(openssl passwd -1 ubuntu)" ubuntu

USER ubuntu
WORKDIR /home/ubuntu/psca
