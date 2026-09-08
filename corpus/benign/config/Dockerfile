# A well-formed image build: base pinned by digest, no fetch-and-execute, no
# secret in a build argument.
FROM python:3.12-slim@sha256:2b2c3a1c19cb96b8ba1f0e7f1e4bdcf3e6b7c1a9f0e1d2c3b4a5968778695a4b

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY . .
USER 65534:65534
CMD ["python", "-m", "app"]
