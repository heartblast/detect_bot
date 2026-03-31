DMZ 구간 웹서버의 웹서빙 경로(root/alias/DocumentRoot) 를 웹서버 설정 “덤프 출력”에서 자동 수집하고, 해당 경로를 스캔하여 용도 부적합 파일(스테이징/반출 징후, 웹쉘/스크립트/아카이브 등) 을 룰 기반으로 탐지한 뒤 표준 JSON 보고서로 산출하는 경량 도구입니다.

**현재 버전: v1.1.3**

실행 시 `NICE DetectBot` ASCII 배너가 stderr로 출력되며, 바로 아래에 버전 정보(예: `Version: v1.1.3`)가 표시됩니다. 배너는 `internal/banner/nice_detectbot.txt`에 템플릿으로 보관되며, Go `embed`로 컴파일 시 바이너리에 포함되어 별도 파일 의존성이 없습니다.

> 목적은 침해 지원이 아닌 통제/탐지/감사입니다.  
> MIME 판별은 `net/http.DetectContentType`(최대 512B sniff) 기반이라 100% 정확하지 않습니다.

---

## 주요 기능

### 1. 웹서빙 경로 자동 수집

* **Nginx**

  * `nginx -T` 출력에서 `root`, `alias` 경로 추출
* **Apache**

  * `apachectl -S` 출력에서 `DocumentRoot` 추출
* **수동 보강**

  * `--watch-dir` 로 추가 감시 경로 지정 가능
* **서버 유형 명시**

  * `--server-type nginx|apache|manual` 지원 

### 2. 웹루트 파일 스캔

수집된 경로를 기준으로 실제 파일 시스템을 순회하며 다음 유형을 탐지합니다.

* 허용 MIME allowlist 위반
* 허용 확장자 allowlist 위반
* 고위험 확장자 탐지
* 확장자–MIME 불일치
* 대용량 파일 탐지
* 최근 변경 파일 중심 점검(`--newer-than-h`) 

### 3. 민감정보 콘텐츠 스캔

텍스트 기반 설정/구성 파일을 선택적으로 본문 스캔합니다.

주요 대상 예:

* `.yaml`, `.yml`, `.json`, `.xml`
* `.properties`, `.conf`, `.env`, `.ini`
* `.txt`, `.config`, `.cfg`, `.toml`

주요 탐지 예:

* JDBC / Redis / MongoDB / PostgreSQL / LDAP 연결 문자열
* password / token / api_key / secret 계열 키
* 비공개 키 / 자격증명 흔적
* 조합형 고위험 패턴

리포트에는 원문 대신 마스킹된 증거만 남기도록 사용하는 것을 권장합니다. 콘텐츠 스캔은 `--content-scan`, `--content-max-bytes`, `--content-max-size-kb`, `--content-ext` 옵션으로 제어됩니다. 

### 4. 개인정보(PII) 패턴 탐지

텍스트 파일 본문에서 개인정보 유출 위험 패턴을 선택적으로 탐지합니다.

대상 예:

* 주민등록번호
* 외국인등록번호
* 여권번호
* 운전면허번호
* 카드번호
* 계좌번호
* 휴대전화번호
* 이메일 주소

지원 옵션 예:

* `--pii-scan`
* `--pii-ext`
* `--pii-max-bytes`
* `--pii-max-size-kb`
* `--pii-max-matches`
* `--pii-mask`
* `--pii-store-sample`
* `--pii-context-keywords` 

### 5. 운영 영향 최소화 옵션

* `--newer-than-h` : 최근 변경 파일 위주 점검
* `--max-depth` : 재귀 깊이 제한
* `--exclude` : 제외 경로 지정
* `--workers` : 스캔 워커 수 조정
* `--hash` : 필요 시에만 SHA-256 계산
* `--max-size-mb` : MIME sniff / 해시 계산 대상 최대 크기 제한
* `--follow-symlink` : 심볼릭 링크 추적 여부 제어 

### 6. 프리셋 / 룰 세부 제어

* 프리셋: `safe`, `balanced`, `deep`, `handover`, `offboarding`
* 룰 개별 제어:

  * `--enable-rules`
  * `--disable-rules`

### 7. Kafka 연계

결과를 로컬 JSON으로 남기면서, 선택적으로 요약 이벤트를 Kafka로 전송할 수 있습니다.

지원 옵션:

* `--kafka-enabled`
* `--kafka-brokers`
* `--kafka-topic`
* `--kafka-client-id`
* `--kafka-tls`
* `--kafka-sasl-enabled`
* `--kafka-username`
* `--kafka-password-env`
* `--kafka-mask-sensitive` 

### 8. Streamlit 리포트 해석기

`streamlit_app/` 아래 리포트 파서 UI에서 JSON 결과를 업로드해 다음을 확인할 수 있습니다.

* 리포트 기본 정보
* 추출된 웹서빙 경로
* 탐지 결과 목록
* 탐지 항목 상세 해석
* 실행 설정
* 원본 JSON
* 스캔 시작 시각(`scan_started_at`)

---

## 설치 / 빌드

### 로컬 빌드

```bash
go build -o detectbot ./cmd/detectbot
```

### Windows PowerShell 예시

```powershell
go build -o detectbot.exe .\cmd\detectbot
```

### Linux 크로스 빌드 예시

```powershell
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -trimpath -ldflags "-s -w" -o dist/detectbot ./cmd/detectbot
```

---

## 사용 예시

### 1) Nginx 덤프 입력 + 스캔

```bash
nginx -T 2>&1 | ./detectbot \
  --server-type nginx \
  --nginx-dump - \
  --scan \
  --newer-than-h 24 \
  --max-depth 10 \
  --exclude /var/cache \
  --out /var/log/detectbot/report-$(date +%F).json
```

### 2) Apache 덤프 입력 + 스캔

```bash
apachectl -S 2>&1 | ./detectbot \
  --server-type apache \
  --apache-dump - \
  --scan \
  --newer-than-h 24 \
  --max-depth 10 \
  --out /var/log/detectbot/report-$(date +%F).json
```

> Apache 환경에서는 `apachectl -S` 출력에 `DocumentRoot`가 보이지 않으면 roots가 비어 있을 수 있습니다.
> 이런 경우 `--watch-dir`로 실제 웹루트/업로드 경로를 함께 지정하는 것이 좋습니다. ([GitHub][3])

### 3) 수동 경로 기반 스캔

```bash
./detectbot \
  --server-type manual \
  --watch-dir /var/www/html \
  --watch-dir /data/upload \
  --scan \
  --newer-than-h 24 \
  --max-depth 8 \
  --out /tmp/report.json
```

### 4) 콘텐츠 스캔 활성화

```bash
nginx -T 2>&1 | ./detectbot \
  --nginx-dump - \
  --scan \
  --content-scan \
  --content-max-bytes 65536 \
  --content-max-size-kb 1024 \
  --content-ext .yaml \
  --content-ext .yml \
  --content-ext .json \
  --content-ext .env \
  --out /tmp/report-content.json
```

### 5) PII 탐지 활성화

```bash
nginx -T 2>&1 | ./detectbot \
  --nginx-dump - \
  --scan \
  --pii-scan \
  --pii-max-bytes 65536 \
  --pii-max-size-kb 256 \
  --pii-ext .yaml \
  --pii-ext .json \
  --pii-ext .txt \
  --pii-ext .log \
  --pii-mask \
  --pii-store-sample \
  --pii-context-keywords \
  --out /tmp/report-pii.json
```

### 6) 해시 포함

```bash
nginx -T 2>&1 | ./detectbot \
  --nginx-dump - \
  --scan \
  --hash \
  --max-size-mb 100 \
  --out /tmp/report-hash.json
```

### 7) 룰 개별 제어

```bash
./detectbot \
  --watch-dir /var/www/html \
  --scan \
  --disable-rules large_file \
  --enable-rules high_risk_extension \
  --out /tmp/report.json
```

### 8) Kafka 전송 활성화

```bash
./detectbot \
  --watch-dir /var/www/html \
  --scan \
  --kafka-enabled \
  --kafka-brokers broker1:9092,broker2:9092 \
  --kafka-topic dmz.scan.findings \
  --kafka-client-id detectbot \
  --kafka-tls \
  --kafka-mask-sensitive \
  --out /tmp/report.json
```

---

## 주요 옵션

### 입력 옵션

* `--server-type`
* `--nginx-dump`
* `--apache-dump`
* `--watch-dir`
* `--config`

### 스캔 / 범위 옵션

* `--scan`
* `--exclude`
* `--max-depth`
* `--newer-than-h`
* `--workers`
* `--hash`
* `--max-size-mb`
* `--follow-symlink`

### 정책 / 룰 옵션

* `--allow-mime-prefix`
* `--allow-ext`
* `--enable-rules`
* `--disable-rules`
* `--preset`

### 콘텐츠 스캔 옵션

* `--content-scan`
* `--content-max-bytes`
* `--content-max-size-kb`
* `--content-ext`

### PII 스캔 옵션

* `--pii-scan`
* `--pii-ext`
* `--pii-max-size-kb`
* `--pii-max-bytes`
* `--pii-max-matches`
* `--pii-mask`
* `--pii-store-sample`
* `--pii-context-keywords`

### 출력 옵션

* `--out`

### Kafka 옵션

* `--kafka-enabled`
* `--kafka-brokers`
* `--kafka-topic`
* `--kafka-client-id`
* `--kafka-tls`
* `--kafka-sasl-enabled`
* `--kafka-username`
* `--kafka-password-env`
* `--kafka-mask-sensitive` 

---

## 설정 파일(`--config`) 사용

현재 `Config` 구조체에는 YAML/JSON 태그가 부여되어 있고, `CHANGES.md` 기준으로는 `snake_case` 설정 키와 Streamlit 스타일 키 호환도 보완된 상태로 정리되어 있습니다.
즉, 현재 문서에는 `--config`를 정식 사용 예시로 포함해도 됩니다. ([GitHub][4])

### YAML 예시

```yaml
server_type: nginx
nginx_dump: "-"
scan: true
out: /tmp/report.json

watch_dirs:
  - /var/www/html

exclude:
  - /var/www/html/cache

max_depth: 8
newer_than_h: 24
workers: 4
hash: false
follow_symlink: false

allow_mime_prefix:
  - text/
  - image/
  - application/javascript

allow_ext:
  - .html
  - .css
  - .js
  - .png
  - .jpg
  - .json

preset: balanced

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
pii_max_matches: 20
pii_mask: true
pii_store_sample: true
pii_context_keywords: true
pii_exts:
  - .txt
  - .log
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

실행 예시:

```bash
nginx -T 2>&1 | ./detectbot --config sample_config.yaml
```

CLI로 명시한 값은 설정 파일 값보다 우선하는 방식으로 사용하는 것이 맞습니다.

---

## Console Output Example

실행 시 배너만 출력되는 것이 아니라 시작, 진행, 완료, 요약 로그가 함께 출력됩니다. 운영자는 배치 로그만 보더라도 실행 시작 여부, 대상 추출 여부, 정상 완료 여부를 빠르게 판단할 수 있습니다.

```text
Version: v1.1.3
[INFO] Scan started at: 2026-03-27T09:15:00+09:00
[INFO] Host: web-dmz-01 (10.10.10.25, linux)
[INFO] Mode: nginx-dump + scan
[INFO] Output file: /tmp/report.json
[INFO] Targets discovered: 4
[INFO] Starting filesystem scan...
[INFO] Scanning root: /var/www/html
[INFO] Scanning root: /srv/www/app
[INFO] Scan completed at: 2026-03-27T09:16:42+09:00
[INFO] Duration: 1m42s
[INFO] Scan roots: 4
[INFO] Findings: 12
[SUMMARY] roots=4 files_scanned=1823 findings=12 high_risk=3 large_files=2 allowlist_violations=7
[INFO] Report written to: /tmp/report.json
```

콘솔 로그는 실행 상태 확인용이고, 상세 탐지 증적은 JSON 리포트에서 확인하는 구조입니다. `--out -` 로 JSON을 stdout에 내보낼 때는 콘솔 로그가 stderr로 우회되어 출력 결과와 충돌하지 않습니다.

## JSON 리포트 구조

최상위 구조 예시:

```json
{
  "report_version": "1.0",
  "generated_at": "2026-03-20T10:00:00+09:00",
  "scan_started_at": "2026-03-20T09:59:58+09:00",
  "host": {
    "hostname": "web-dmz-01",
    "ip_addresses": [
      "10.10.10.25"
    ],
    "primary_ip": "10.10.10.25",
    "os_type": "linux",
    "os_name": "Rocky Linux",
    "os_version": "8.10",
    "platform": "linux/amd64",
    "collected_at": "2026-03-20T09:59:58+09:00"
  },
  "inputs": [
    "nginx-dump:-"
  ],
  "config": {},
  "active_rules": [
    "allowlist",
    "high_risk_extension",
    "large_file",
    "ext_mime_mismatch"
  ],
  "roots": [],
  "findings": [],
  "stats": {
    "roots_count": 0,
    "scanned_files": 0,
    "findings_count": 0
  }
}
```

`host.hostname`, `host.primary_ip`, `host.os_type` 는 운영자가 리포트만 보더라도 어느 서버 결과인지 즉시 식별하기 위한 핵심 필드입니다. Streamlit 리포트 파서와 DetectBot Portal 목록/상세 화면에서도 같은 정보를 함께 표시합니다.

### finding 예시

```json
{
  "path": "/var/www/html/.env",
  "real_path": "/var/www/html/.env",
  "size_bytes": 4096,
  "mod_time": "2026-03-20T09:40:00+09:00",
  "perm": "-rw-r--r--",
  "ext": ".env",
  "mime_sniff": "text/plain; charset=utf-8",
  "reasons": [
    "ext_not_in_allowlist",
    "secret_patterns"
  ],
  "severity": "high"
}
```

Manual verification checklist:
1. Run with only a YAML config file.
2. Run with only a JSON config file.
3. Run with `--config` plus a few CLI overrides such as `--workers` or `--watch-dir`.
4. Run without `--config` and confirm existing CLI-only behavior is unchanged.
