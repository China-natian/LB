# Build onego (patched gogo) inside the image so hosts do not need a Go
# toolchain and the binary always matches third_party/onego/patches.
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS onego-build
WORKDIR /src
COPY third_party/onego/build-src/ /src/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -tags "forceposix,noembed,osusergo,netgo" \
    -ldflags "-s -w -X 'github.com/chainreactors/onego/v2/core.ver=lb-1'" \
    -o /out/onego .

# Pinned helper binaries. Their release artifacts embed the credential rules and
# dictionaries, so no template checkout or local Go toolchain is needed.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS tools
ARG ZOMBIE_VERSION=v1.3.0
ARG SPRAY_VERSION=v0.3.2
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /out
RUN curl -fsSL -o /out/zombie "https://github.com/chainreactors/zombie/releases/download/${ZOMBIE_VERSION}/zombie_linux_amd64" \
    && echo "94cc277b812d5b056984fb2206d32d9911791feea7a0dc811c2b196a82666325  /out/zombie" | sha256sum -c -
RUN curl -fsSL -o /out/spray "https://github.com/chainreactors/spray/releases/download/${SPRAY_VERSION}/spray_linux_amd64" \
    && echo "5e6c778790a93c79110394a1c43f8d1902e20c69f5f03e544347fda7cf9863e8  /out/spray" | sha256sum -c -

FROM --platform=amd64 kalilinux/kali-rolling:latest

RUN apt update && \
    apt -y install kali-linux-headless && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash kali && \
    echo "kali ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
USER kali

RUN sudo apt update && \
    sudo apt install -y bsdextrautils npm jq iputils-ping sshpass ncat rlwrap libcap2-bin \
    bloodyad coercer enum4linux-ng pwncat chisel-common-binaries \
    dirsearch yq krb5-user gitleaks naabu nikto netexec adb subfinder dnsx impacket-scripts \
    python3-pwntools python3-pymongo python3-redis python3-pymysql python3-dev \
    redis-tools certipy-ad jadx feroxbuster cmake pkg-config strace cpio seclists && \
    (sudo apt install -y kubectl || sudo apt install -y kubernetes-client || true) && \
    sudo ln -sf "$(ls /usr/share/chisel-common-binaries/chisel_*_linux_amd64 | head -1)" /usr/local/bin/chisel && \
    sudo apt clean && \
    sudo rm -rf /var/lib/apt/lists/*

# kali-linux-headless does not pull the Kubernetes client, and skills reference kubectl.
RUN if ! command -v kubectl >/dev/null 2>&1; then \
        curl -fsSL --retry 3 -o /tmp/kubectl \
            "https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl" && \
        sudo install -m 0755 /tmp/kubectl /usr/local/bin/kubectl && \
        rm -f /tmp/kubectl; \
    fi

RUN sudo npm install -g @playwright/cli@latest

RUN cd /tmp && playwright-cli install

RUN cd /tmp && \
    wget -q "https://github.com/projectdiscovery/katana/releases/download/v1.5.0/katana_1.5.0_linux_amd64.zip" -O katana.zip && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v3.7.1/nuclei_3.7.1_linux_amd64.zip" -O nuclei.zip && \
    wget -q "https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-amd64.tar.gz" -O dalfox.tar.gz && \
    wget -q "https://github.com/BishopFox/cloudfox/releases/download/v2.0.1/cloudfox-linux-amd64.zip" -O cloudfox.zip && \
    wget -q "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64" -O kerbrute && \
    git clone --depth 1 "https://github.com/projectdiscovery/nuclei-templates.git" /home/kali/.local/nuclei-templates && \
    unzip -q katana.zip katana && sudo mv katana /usr/local/bin/ && \
    unzip -q nuclei.zip nuclei && sudo mv nuclei /usr/local/bin/ && \
    tar -xzf dalfox.tar.gz && sudo mv dalfox-linux-amd64 /usr/local/bin/dalfox && \
    unzip -q cloudfox.zip cloudfox/cloudfox && sudo mv cloudfox/cloudfox /usr/local/bin/ && \
    sudo cp kerbrute /usr/local/bin/ && \
    nuclei -ut && \
    sudo rm -rf /tmp/*

RUN mkdir -p /home/kali/knowledges && cd /home/kali/knowledges && \
    git clone --depth=1 https://github.com/swisskyrepo/PayloadsAllTheThings.git && \
    git clone --depth=1 https://github.com/swisskyrepo/InternalAllTheThings.git && \
    git clone --depth=1 https://github.com/HackTricks-wiki/hacktricks.git && \
    git clone --depth=1 https://github.com/HackTricks-wiki/hacktricks-cloud.git

RUN mkdir -p /home/kali/tools && cd /home/kali/tools && \
    wget -q "https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar" -O ysoserial.jar && \
    git clone --depth=1 https://github.com/ticarpi/jwt_tool.git && \
    cd jwt_tool && pip3 install -r requirements.txt --break-system-packages && \
    git clone --depth=1 https://github.com/IOActive/jdwp-shellifier.git

# JDK 8 (javac) for compiling Java payloads; kept separate from the distro JDK so the
# default `java` stays on the newer version.
RUN cd /tmp && \
    wget -q "https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u422-b05/OpenJDK8U-jdk_x64_linux_hotspot_8u422b05.tar.gz" -O jdk8.tar.gz && \
    sudo mkdir -p /opt/jdk8 && \
    sudo tar -xzf jdk8.tar.gz -C /opt/jdk8 --strip-components=1 && \
    sudo ln -sf /opt/jdk8/bin/javac /usr/local/bin/javac8 && \
    sudo ln -sf /opt/jdk8/bin/java /usr/local/bin/java8 && \
    sudo rm -rf /tmp/*

RUN cd /tmp && \
    wget -q "https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz" -O maven.tar.gz && \
    sudo mkdir -p /opt/maven && \
    sudo tar -xzf maven.tar.gz -C /opt/maven --strip-components=1 && \
    sudo ln -sf /opt/maven/bin/mvn /usr/local/bin/mvn && \
    sudo rm -rf /tmp/*

# Deserialization payload dependencies (Shiro rememberMe, CommonsBeanutils/Collections gadgets).
RUN mkdir -p /home/kali/tools/jars && cd /home/kali/tools/jars && \
    wget -q "https://repo1.maven.org/maven2/org/apache/shiro/shiro-core/1.2.4/shiro-core-1.2.4.jar" && \
    wget -q "https://repo1.maven.org/maven2/commons-beanutils/commons-beanutils/1.9.2/commons-beanutils-1.9.2.jar" && \
    wget -q "https://repo1.maven.org/maven2/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar" && \
    wget -q "https://repo1.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar" && \
    wget -q "https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar"

RUN mkdir -p /home/kali/pocs && cd /home/kali/pocs && \
    git clone --depth=1 https://github.com/iSee857/CVE-PoC.git && \
    git clone --depth=1 https://github.com/zhzyker/exphub.git && \
    git clone --depth=1 https://github.com/passwa11/2023Hvv_.git && \
    git clone --depth=1 https://github.com/Threekiii/Awesome-POC.git && \
    git clone --depth=1 https://github.com/vulhub/vulhub.git

RUN cd /tmp && \
    wget -q "https://github.com/BurntSushi/ripgrep/releases/download/15.1.0/ripgrep_15.1.0-1_amd64.deb" -O ripgrep.deb && \
    wget -q "https://github.com/sharkdp/fd/releases/download/v10.4.2/fd_10.4.2_amd64.deb" -O fd.deb && \
    wget -q "https://github.com/vi/websocat/releases/download/v1.13.0/websocat.x86_64-unknown-linux-musl" -O websocat && \
    sudo apt install ./ripgrep.deb ./fd.deb && \
    sudo install -m 0755 websocat /usr/local/bin/websocat && \
    sudo rm -rf /tmp/* && \
    sudo apt clean && \
    sudo rm -rf /var/lib/apt/lists/*

RUN pip3 install adidnsdump --break-system-packages
    
RUN pip3 install tccli awscli --break-system-packages && \
    sudo bash -c "$(curl -fsSL https://aliyuncli.alicdn.com/install.sh)"

RUN sudo npm install -g @openai/codex@0.118.0
RUN sudo npm install -g @anthropic-ai/claude-code@2.1.98
RUN sudo npm install -g @mariozechner/pi-coding-agent@0.73.0

RUN sudo chmod +x /usr/local/bin/kerbrute
RUN if ! command -v certipy >/dev/null 2>&1 && [ -x /usr/bin/certipy-ad ]; then \
        sudo ln -sf /usr/bin/certipy-ad /usr/local/bin/certipy; \
    fi
# Skills still call the legacy `crackmapexec` name; netexec is wire-compatible for
# the SMB/LDAP/WinRM sweeps used here.
RUN if command -v nxc >/dev/null 2>&1; then \
        sudo ln -sf "$(command -v nxc)" /usr/local/bin/crackmapexec; \
    fi
# Debian installs the fd binary as fdfind; skills call `fd`.
RUN if ! command -v fd >/dev/null 2>&1 && command -v fdfind >/dev/null 2>&1; then \
        sudo ln -sf "$(command -v fdfind)" /usr/local/bin/fd; \
    fi
# Skills call impacket examples by their upstream names (secretsdump.py, psexec.py);
# Kali exposes them as impacket-* wrappers. Add aliases without shadowing real tools.
RUN if command -v impacket-secretsdump >/dev/null 2>&1; then \
        for script in /usr/bin/impacket-*; do \
            [ -x "$script" ] || continue; \
            base=$(basename "$script"); base=${base#impacket-}; \
            for target in "$base" "$base.py"; do \
                if [ ! -e "/usr/local/bin/$target" ] && ! command -v "$target" >/dev/null 2>&1; then \
                    sudo ln -s "$script" "/usr/local/bin/$target"; \
                fi; \
            done; \
        done; \
    fi

# Kali ships nmap/masscan with NET_ADMIN in their file capabilities, but the default
# Docker bounding set drops it, so even connect scans fail with EPERM. nmap is a
# wrapper script on Kali; capabilities must be set on the real ELF, not the wrapper.
RUN sudo sh -c 'command -v setcap >/dev/null 2>&1 || exit 0; \
        set_caps() { [ -f "$1" ] || return 0; setcap cap_net_bind_service,cap_net_raw=eip "$1" || exit 1; }; \
        set_caps /usr/lib/nmap/nmap; \
        if [ ! -f /usr/lib/nmap/nmap ]; then \
            path="$(command -v nmap 2>/dev/null)" && set_caps "$(readlink -f "$path")"; \
        fi; \
        path="$(command -v masscan 2>/dev/null)" && set_caps "$(readlink -f "$path")"; \
        exit 0'

RUN mkdir -p /home/kali/.config/nuclei && \
    echo >> /home/kali/.config/nuclei/config.yaml && \
    echo "disable-update-check: true" >> /home/kali/.config/nuclei/config.yaml && \
    echo "update-template-dir: /home/kali/.local/nuclei-templates" >> /home/kali/.config/nuclei/config.yaml && \
    rm -rf /home/kali/nuclei-templates
RUN sudo rm -rf /usr/lib/llvm-*/build && \
    sudo chmod o+rx /usr/lib/mysql/plugin/auth_pam_tool_dir /etc/ssl/private
RUN printf '%s\n' 'PS1="${PS1%\\n*} \[\033[0;36m\]\D{%y-%m-%d} - \t\[\033[;32m\]\n${PS1##*\\n}"' >> /home/kali/.bashrc && \
    mkdir -p /home/kali/workspace && cd /home/kali/workspace && git init
ENV TZ=Asia/Shanghai
ENV PATH="/home/kali/.local/bin:${PATH}"
ENV PLAYWRIGHT_MCP_BROWSER=chromium
ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
ENV PYTHONUNBUFFERED=1

RUN printf '%s\n' '{"hasCompletedOnboarding": true, "autoUpdaterStatus": "disabled"}' > /home/kali/.claude.json

COPY ./container/.agents /home/kali/workspace/.agents
COPY ./container/.agents /home/kali/workspace/.claude
COPY ./container/AGENTS.md /home/kali/workspace/AGENTS.md
COPY ./container/AGENTS.md /home/kali/workspace/CLAUDE.md
COPY ./container/skills-cli /usr/local/bin/skills
COPY --from=onego-build /out/onego /usr/local/bin/onego
COPY --from=tools /out/zombie /usr/local/bin/zombie
COPY --from=tools /out/spray /usr/local/bin/spray
RUN sudo chmod 755 /usr/local/bin/skills /usr/local/bin/onego /usr/local/bin/zombie /usr/local/bin/spray \
    && mkdir -p /home/kali/skills /home/kali/.local/bin

# kali-linux-headless can leave the home directory root-owned, which prevents the
# worker CLI from creating ~/.codex or ~/.config at startup.
RUN sudo chown kali:kali /home/kali

WORKDIR /home/kali/workspace