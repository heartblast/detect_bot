# Detect Bot

`Detect Bot`은 DMZ 구간 웹서버에서 웹서빙 경로를 수집하고, 해당 경로 아래 파일을 스캔해 웹 노출에 부적절한 파일이나 민감정보 흔적을 JSON 리포트로 남기는 Go 기반 점검 도구입니다.

현재 저장소 모듈 경로는 `github.com/heartblast/detect_bot`입니다.

## 무엇을 하는가

- `nginx -T` 출력에서 `root`, `alias` 경로를 추출합니다.
- `apachectl -S` 출력에서 `DocumentRoot` 경로를 추출합니다.
- `--watch-dir`로 수동 스캔 경로를 추가할 수 있습니다.
- 수집한 루트 경로를 순회하며 파일 메타데이터와 일부 콘텐츠를 검사합니다.
- 결과를 JSON 리포트로 저장하거나 stdout으로 출력할 수 있습니다.
- 선택적으로 Kafka에 요약 이벤트를 전송할 수 있습니다.

## 현재 구현 기준 주요 기능

### 1. 웹 루트 수집

- Nginx: `root`, `alias`
- Apache: `DocumentRoot`
- Manual: `--watch-dir`

수집된 루트는 정규화되며, 가능한 경우 symlink 실제 경로도 함께 기록됩니다.

### 2. 파일 시스템 스캔

현재 스캔 시 다음 제어가 지원됩니다.

- `--max-depth`: 재귀 깊이 제한
- `--exclude`: 제외 경로 prefix
- `--newer-than-h`: 최근 N시간 내 수정 파일만 평가
- `--workers`: 병렬 스캔 워커 수
- `--follow-symlink`: symlink/reparse point 추적 여부
- `--max-size-mb`: MIME sniff/향후 해시 대상 파일의 최대 크기 제한

### 3. 기본 룰

현재 코드에서 기본 활성화되는 룰은 아래 4개입니다.

- `allowlist`
- `high_risk_ext`
- `large_file`
- `ext_mime_mismatch`

각 룰이 만들어내는 대표 reason 코드는 다음과 같습니다.

- `mime_not_in_allowlist`
- `ext_not_in_allowlist`
- `high_risk_extension`
- `large_file_in_web_path`
- `ext_mime_mismatch_image`
- `ext_mime_mismatch_archive`

### 4. 콘텐츠 기반 민감정보 탐지

`--content-scan`을 켜면 텍스트 계열 파일 샘플을 읽어 아래 범주의 패턴을 탐지합니다.

- DB/서비스 연결 문자열
- 비밀번호/토큰/API 키 등 자격증명
- private key 블록
- 내부망 IP / 내부 도메인
- 위험 조합 패턴

대표 매칭 코드 예시:

- `connection_jdbc_url`
- `connection_redis_uri`
- `connection_mongodb_uri`
- `credential_password`
- `credential_api_key`
- `private_key_rsa`
- `internal_endpoint_private_ip`
- `combo_jdbc_with_credentials`

### 5. PII 탐지

`--pii-scan`을 켜면 개인정보 패턴을 탐지합니다.

- 주민등록번호
- 외국인등록번호
- 여권번호
- 운전면허번호
- 카드번호
- 계좌번호
- 휴대전화번호
- 이메일

대표 매칭 코드 예시:

- `resident_registration_number`
- `foreigner_registration_number`
- `passport_number`
- `drivers_license`
- `credit_card`
- `bank_account`
- `mobile_phone`
- `email`

## 제한사항

- MIME 판별은 `net/http.DetectContentType` 기반의 샘플 sniff 방식입니다.
- 콘텐츠/PII 스캔은 파일 전체가 아니라 제한된 샘플만 읽습니다.
- `--hash` 플래그와 `sha256` 필드는 존재하지만, 현재 구현에서는 `sha256` 값이 실제로 채워지지 않습니다.
- Kafka의 SASL은 플래그와 설정은 있으나 현재는 stub 상태이며 실제 인증 로직은 구현되어 있지 않습니다.
- Kafka TLS는 `InsecureSkipVerify: true`로 동작합니다.

## 설치 및 빌드

- Build/CI toolchain: Go 1.26.1
- `go.mod` language version: Go 1.25.0

### 로컬 빌드

```bash
go build -o detectbot ./cmd/detectbot
```

### Windows PowerShell

```powershell
go build -o detectbot.exe .\cmd\detectbot
```

### 배포용 빌드 스크립트

리포지토리에는 아래 스크립트가 포함되어 있습니다.

- `build.sh`
- `build.ps1`

`build.sh` 기준 산출물 예:

- `dist/detectbot_windows_amd64_v1_1_3.exe`
- `dist/detectbot_linux_amd64_v1_1_3`
- `dist/detectbot_darwin_amd64_v1_1_3`
- `dist/detectbot_darwin_arm64_v1_1_3`

## 빠른 사용 예시

### Nginx dump 기반

```bash
nginx -T 2>&1 | ./detectbot \
  --server-type nginx \
  --nginx-dump - \
  --scan \
  --out /tmp/report.json
```

### Apache dump 기반

```bash
apachectl -S 2>&1 | ./detectbot \
  --server-type apache \
  --apache-dump - \
  --scan \
  --out /tmp/report.json
```

### 수동 경로 기반

```bash
./detectbot \
  --server-type manual \
  --watch-dir /var/www/html \
  --watch-dir /srv/uploads \
  --scan \
  --out /tmp/report.json
```

### 콘텐츠 스캔 포함

```bash
./detectbot \
  --server-type manual \
  --watch-dir /var/www/html \
  --scan \
  --content-scan \
  --content-ext .yaml \
  --content-ext .env \
  --out /tmp/report-content.json
```

### PII 스캔 포함

```bash
./detectbot \
  --server-type manual \
  --watch-dir /var/www/html \
  --scan \
  --pii-scan \
  --pii-ext .json \
  --pii-ext .txt \
  --pii-mask \
  --pii-store-sample \
  --out /tmp/report-pii.json
```

## CLI 옵션

### 입력 옵션

- `--server-type nginx|apache|manual`
- `--nginx-dump <path|- >`
- `--apache-dump <path|- >`
- `--watch-dir <path>` 반복 가능
- `--config <yaml|json>`

### 스캔 옵션

- `--scan`
- `--exclude <path>` 반복 가능
- `--max-depth <n>`
- `--newer-than-h <hours>`
- `--workers <n>`
- `--hash`
- `--max-size-mb <n>`
- `--follow-symlink`

### 정책/룰 옵션

- `--allow-mime-prefix <prefix>` 반복 가능
- `--allow-ext <ext>` 반복 가능
- `--enable-rules <name>` 반복 가능 또는 comma-separated
- `--disable-rules <name>` 반복 가능 또는 comma-separated
- `--preset safe|balanced|deep|handover|offboarding`

### 콘텐츠 스캔 옵션

- `--content-scan`
- `--content-max-bytes <n>`
- `--content-max-size-kb <n>`
- `--content-ext <ext>` 반복 가능

### PII 스캔 옵션

- `--pii-scan`
- `--pii-ext <ext>` 반복 가능
- `--pii-max-size-kb <n>`
- `--pii-max-bytes <n>`
- `--pii-max-matches <n>`
- `--pii-mask`
- `--pii-store-sample`
- `--pii-context-keywords`

### 출력 옵션

- `--out <path|->`

### Kafka 옵션

- `--kafka-enabled`
- `--kafka-brokers <a,b,c>`
- `--kafka-topic <topic>`
- `--kafka-client-id <id>`
- `--kafka-tls`
- `--kafka-sasl-enabled`
- `--kafka-username <user>`
- `--kafka-password-env <env>`
- `--kafka-mask-sensitive`

## 설정 파일

`--config`로 YAML 또는 JSON 설정 파일을 읽을 수 있습니다.

지원 포맷:

- `.yaml`
- `.yml`
- `.json`

CLI에서 명시한 값이 설정 파일보다 우선합니다.

호환 alias도 일부 지원합니다.

- `watch_dir` -> `watch_dirs`
- `content_ext` -> `content_exts`
- `pii_ext` -> `pii_exts`
- `output` -> `out`

### YAML 예시

```yaml
server_type: nginx
nginx_dump: "-"
scan: true
out: /tmp/report.json

watch_dirs:
  - /var/www/html

exclude:
  - /var/cache

max_depth: 12
max_size_mb: 100
newer_than_h: 24
workers: 4
hash: false
follow_symlink: false

allow_mime_prefix:
  - text/html
  - application/json
  - image/

allow_ext:
  - .html
  - .css
  - .js
  - .json
  - .png

content_scan: true
content_max_bytes: 65536
content_max_size_kb: 1024
content_exts:
  - .yaml
  - .yml
  - .json
  - .env

pii_scan: true
pii_max_bytes: 65536
pii_max_size_kb: 256
pii_max_matches: 5
pii_mask: true
pii_store_sample: true
pii_context_keywords: true
pii_exts:
  - .txt
  - .json

kafka:
  enabled: false
  brokers:
    - broker1:9092
  topic: dmz.scan.findings
  client_id: detectbot
  tls: false
  sasl_enabled: false
  username: ""
  password_env: ""
  mask_sensitive: true
```

## 출력 형식

리포트는 pretty JSON으로 저장됩니다.

최상위 필드:

- `report_version`
- `generated_at`
- `scan_started_at`
- `host`
- `inputs`
- `config`
- `active_rules`
- `roots`
- `findings`
- `stats`

### `host` 예시

```json
{
  "hostname": "web-dmz-01",
  "ip_addresses": ["10.10.10.25"],
  "primary_ip": "10.10.10.25",
  "os_type": "linux",
  "os_name": "Rocky Linux",
  "os_version": "8.10",
  "platform": "linux/amd64",
  "collected_at": "2026-03-31T10:00:00+09:00"
}
```

### `roots` 예시

```json
[
  {
    "path": "/var/www/html",
    "real_path": "/srv/www/html",
    "source": "nginx.root",
    "context_hint": "/etc/nginx/nginx.conf:42 | server_name=example.com"
  }
]
```

### `finding` 예시

```json
{
  "path": "/var/www/html/.env",
  "real_path": "/srv/www/html/.env",
  "size_bytes": 4096,
  "mod_time": "2026-03-31T09:30:00+09:00",
  "perm": "-rw-r--r--",
  "ext": ".env",
  "mime_sniff": "text/plain; charset=utf-8",
  "reasons": [
    "ext_not_in_allowlist",
    "credential_password"
  ],
  "severity": "critical",
  "matched_patterns": [
    "credential_password"
  ],
  "evidence_masked": [
    "password=***"
  ],
  "content_flags": "truncated",
  "root_matched": "/var/www/html",
  "root_source": "manual",
  "url_exposure_heuristic": "potentially_web_reachable"
}
```

## Kafka 전송

Kafka를 켜면 전체 리포트가 아니라 요약 이벤트가 전송됩니다.

현재 이벤트에는 아래 정보가 포함됩니다.

- `host`
- `generated_at`
- `roots_count`
- `findings[].path`
- `findings[].severity`
- `findings[].reasons`

`--kafka-mask-sensitive`가 켜져 있으면 Kafka 이벤트의 경로는 파일명만 남기고 마스킹됩니다.

## 실행 시 로그

실행 중 콘솔에는 stderr로 진행 로그가 출력됩니다.

예:

```text
Version: v1.1.3
[INFO] Scan started at: 2026-03-31T10:00:00+09:00
[INFO] Host: web-dmz-01 (10.10.10.25, linux)
[INFO] Mode: nginx-dump + scan
[INFO] Output file: /tmp/report.json
[INFO] Targets discovered: 3
[INFO] Starting filesystem scan...
[INFO] Scanning root: /var/www/html
[INFO] Scan completed at: 2026-03-31T10:00:08+09:00
[INFO] Duration: 8s
[INFO] Scan roots: 3
[INFO] Findings: 7
[SUMMARY] roots=3 files_scanned=812 findings=7 high_risk=1 large_files=2 allowlist_violations=4
[INFO] Report written to: /tmp/report.json
```

`--out -`를 사용하면 JSON은 stdout으로, 로그는 stderr로 분리됩니다.

## 보조 UI

이 저장소에는 보조 UI도 포함되어 있습니다.

- `streamlit_app/`: 옵션 생성과 리포트 해석용 Streamlit UI
- `detectbot_portal/`: 리포트 적재/조회 중심 포털 UI

CLI 스캐너의 핵심 실행 파일은 `cmd/detectbot`입니다.

## 검증 명령

```bash
go test ./...
go vet ./...
go build ./cmd/detectbot
```
