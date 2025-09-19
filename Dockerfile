FROM python:3.11-slim

RUN apt-get update &&     apt-get install -y --no-install-recommends     nmap fping masscan iproute2 &&     rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pandas python-nmap

WORKDIR /app
COPY binderscan.py /app/binderscan.py
RUN mkdir /app/logs

ENTRYPOINT ["python", "/app/binderscan.py"]
