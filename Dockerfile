FROM python:3.12-slim
WORKDIR /app
COPY sshdetect.py evaluate.py gen_sample_log.py ./
ENTRYPOINT ["python", "sshdetect.py"]
# docker build -t sshdetect .
# docker run --rm -v /var/log:/logs:ro sshdetect /logs/auth.log --year 2026
