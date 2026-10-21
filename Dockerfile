# VibeGuard API for Render's free plan (512 MB RAM, 0.1 CPU); the UI is static on Firebase Hosting. See VibeGuard.md §22.
# Every scanner is pinned. njsscan is left out (≈100 s of CPU per scan here, for findings semgrep and our rules already make).

FROM node:22-bookworm-slim AS node
RUN npm install -g --omit=dev retire@6.1.0 lockfile-lint@5.1.0

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl && rm -rf /var/lib/apt/lists/*

# release binaries
RUN curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks \
 && curl -fsSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.3/trufflehog_3.99.3_linux_amd64.tar.gz | tar -xz -C /usr/local/bin trufflehog \
 && curl -fsSL -o /usr/local/bin/osv-scanner https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64 \
 && chmod +x /usr/local/bin/osv-scanner

# node only for retire.js and lockfile-lint
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/retire /usr/local/lib/node_modules/retire
COPY --from=node /usr/local/lib/node_modules/lockfile-lint /usr/local/lib/node_modules/lockfile-lint
RUN ln -s /usr/local/lib/node_modules/retire/lib/cli.js /usr/local/bin/retire \
 && ln -s /usr/local/lib/node_modules/lockfile-lint/bin/lockfile-lint.js /usr/local/bin/lockfile-lint

# Python scanners in their own venv, so their pins never fight the app's
RUN python -m venv /opt/scanners \
 && /opt/scanners/bin/pip install --no-cache-dir semgrep==1.181.0 bandit==1.9.4 zizmor==1.31.1 ast-grep-cli==0.51.0 \
 && ln -s /opt/scanners/bin/semgrep /opt/scanners/bin/pysemgrep /opt/scanners/bin/bandit /opt/scanners/bin/zizmor \
          /opt/scanners/bin/ast-grep /usr/local/bin/

WORKDIR /app/backend
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ .
COPY sample-repo/ /app/sample-repo/
# Semgrep registry rules baked in: no rule download per scan
RUN python rules/fetch_registry.py

# scans read untrusted code: run as an unprivileged user that can only write its own database and temp files
RUN useradd --create-home app && chown -R app /app/backend
USER app
ENV PYTHONUNBUFFERED=1 VIBEGUARD_DB=/app/backend/vibeguard.db
EXPOSE 10000
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --proxy-headers --forwarded-allow-ips '*'"]
