# Multi-stage, rootless Dockerfile for ultra-secure Python RDP app
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requesiments.txt .
RUN pip install --user --upgrade pip \
    && pip install --user -r requesiments.txt

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
COPY . .
USER nobody
EXPOSE 8000
CMD ["python3", "xploit_ninja_official.py"]