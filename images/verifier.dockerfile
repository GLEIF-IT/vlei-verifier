FROM 2byrds/keripy:latest

WORKDIR /usr/local/var

RUN mkdir vlei-verifier
COPY . /usr/local/var/vlei-verifier

WORKDIR /usr/local/var/vlei-verifier/

RUN pip install -r requirements.txt

ENTRYPOINT ["verifier", "server", "start", "--config-dir", "scripts", "--config-file", "verifier-config-rootsid.json"]