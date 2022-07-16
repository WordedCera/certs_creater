FROM python:3.10

USER root

COPY requirements.cfg requirements.cfg
COPY main.sh /main.sh
COPY . .

RUN pip install --no-cache-dir -r requirements.cfg && chmod +x /main.sh

ENTRYPOINT [ "bash", "/main.sh" ]