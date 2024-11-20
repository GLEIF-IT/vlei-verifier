FROM weboftrust/keri:1.2.0-rc4

WORKDIR /usr/local/var

RUN mkdir vlei-verifier
COPY . /usr/local/var/vlei-verifier

WORKDIR /usr/local/var/vlei-verifier/

RUN pip install -r requirements.txt

ENTRYPOINT ["verifier", "server", "start", "--config-dir", "scripts", "--config-file", "verifier-config-public.json"]