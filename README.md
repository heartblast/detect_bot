# DMZ Webroot Scanner

DMZ 구간 웹서버의 웹서빙 경로(`root` / `alias` / `DocumentRoot`)를 웹서버 설정 덤프 출력에서 수집하고,  
해당 경로를 스캔하여 웹루트에 존재하면 부적절한 파일(스테이징/반출 징후, 웹쉘·스크립트·아카이브·설정 유출 파일 등)을  
룰 기반으로 탐지한 뒤 JSON 보고서로 산출하는 경량 점검 도구입니다.

이 도구는 Nginx와 Apache 환경에서 실제 웹서빙에 사용되는 경로를 기준으로 점검 대상을 좁혀,  
운영 영향은 최소화하면서도 웹루트 내 이상 파일과 유출위험 파일을 조기에 식별할 수 있도록 설계되었습니다. 

> 목적은 침해 지원이 아닌 **통제 / 탐지 / 감사**입니다.  
> MIME 판별은 `net/http.DetectContentType` 기반이므로 100% 정확도 보장은 어렵습니다.

---

## 프로그램 소개

`dmz_webroot_scanner`는 DMZ 구간 웹서버에서 외부에 노출될 수 있는 웹서빙 경로를 식별하고,  
그 경로 안에 존재하는 파일을 점검하여 **용도에 맞지 않는 파일**, **유출위험이 있는 설정/구성 파일**,  
**스테이징 또는 반출 징후로 볼 수 있는 파일**을 찾아내기 위한 보안 점검 도구입니다.

단순히 디렉터리 전체를 무차별적으로 점검하는 방식이 아니라,  
웹서버 설정에서 실제 서비스 경로 후보를 추출한 뒤 그 범위를 중심으로 점검하므로  
운영 중인 서버에도 비교적 가볍게 적용할 수 있습니다. 

또한 탐지 결과는 표준 JSON 보고서로 저장되므로,  
현장 점검 증빙, 사후 분석, Streamlit 기반 결과 해석 UI, 향후 SIEM 연계까지 고려한 형태로 활용할 수 있습니다.  
실제 코드 기준으로 리포트에는 `scan_started_at`, `roots`, `findings`, `stats`, `config`, `active_rules` 등이 포함됩니다.

---

## 개발 목적 및 취지

DMZ 구간의 웹서버는 외부와 맞닿아 있는 특성상,  
웹루트 또는 업로드/alias 경로에 본래 서비스 목적과 맞지 않는 파일이 생성될 경우  
정보유출, 우회 저장, 반출 준비, 악성 스크립트 배치 등의 보안 리스크로 이어질 수 있습니다.

이 프로그램은 이러한 문제를 다음과 같은 목적 아래 개발되었습니다.

- 웹서버 설정 기준으로 실제 웹서빙 경로를 재현 가능하게 식별
- 웹루트 내 부적절 파일을 조기에 탐지하여 이상 징후를 빠르게 확인
- 설정 파일, 비밀정보, 개인정보 패턴 등 유출위험 정보를 선택적으로 식별
- 점검 결과를 표준 JSON으로 남겨 증빙과 후속 조치에 활용
- 운영 영향이 큰 전수 점검보다는 범위 제한, 최근 변경 중심, 깊이 제한 등으로 부하를 통제

즉, 이 도구의 핵심 취지는  
**“DMZ 웹서버의 실제 서비스 경로를 기준으로, 외부 노출 가능성이 있는 파일과 유출 징후를 조기에 탐지하고,  
그 결과를 표준화된 보고서로 남겨 통제의 실효성을 높이는 것”** 입니다.

---

## 기대 효과

- 웹루트 내 이상 파일의 조기 발견
- 유출위험 설정/구성 파일의 식별
- 점검 증빙의 표준화
- 반복 점검 및 운영 적용 용이
- 향후 Streamlit 분석 UI 및 SIEM 연계 기반 마련

---

## 현재 버전

코드 기준 기본 버전 문자열은 현재 `v1.1.2`이며, 실행 시 `DetectBot` ASCII 배너와 함께 버전 정보가 `stderr`로 출력됩니다.  


예시:

```text
[NICE DetectBot 배너]
Version: v1.1.2
````

배너는 `internal/banner/nice_detectbot.txt` 파일을 `go:embed`로 바이너리에 포함하는 방식입니다. 

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
go build -o dmz_webroot_scanner ./cmd/dmz_webroot_scanner
```

### Windows PowerShell 예시

```powershell
go build -o dmz_webroot_scanner.exe .\cmd\dmz_webroot_scanner
```

### Linux 크로스 빌드 예시

```powershell
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -trimpath -ldflags "-s -w" -o dist/dmz_webroot_scanner ./cmd/dmz_webroot_scanner
```

---

## 사용 예시

### 1) Nginx 덤프 입력 + 스캔

```bash
nginx -T 2>&1 | ./dmz_webroot_scanner \
  --server-type nginx \
  --nginx-dump - \
  --scan \
  --newer-than-h 24 \
  --max-depth 10 \
  --exclude /var/cache \
  --out /var/log/dmz_webroot_scanner/report-$(date +%F).json
```

### 2) Apache 덤프 입력 + 스캔

```bash
apachectl -S 2>&1 | ./dmz_webroot_scanner \
  --server-type apache \
  --apache-dump - \
  --scan \
  --newer-than-h 24 \
  --max-depth 10 \
  --out /var/log/dmz_webroot_scanner/report-$(date +%F).json
```

> Apache 환경에서는 `apachectl -S` 출력에 `DocumentRoot`가 보이지 않으면 roots가 비어 있을 수 있습니다.
> 이런 경우 `--watch-dir`로 실제 웹루트/업로드 경로를 함께 지정하는 것이 좋습니다. ([GitHub][3])

### 3) 수동 경로 기반 스캔

```bash
./dmz_webroot_scanner \
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
nginx -T 2>&1 | ./dmz_webroot_scanner \
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
nginx -T 2>&1 | ./dmz_webroot_scanner \
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
nginx -T 2>&1 | ./dmz_webroot_scanner \
  --nginx-dump - \
  --scan \
  --hash \
  --max-size-mb 100 \
  --out /tmp/report-hash.json
```

### 7) 룰 개별 제어

```bash
./dmz_webroot_scanner \
  --watch-dir /var/www/html \
  --scan \
  --disable-rules large_file \
  --enable-rules high_risk_extension \
  --out /tmp/report.json
```

### 8) Kafka 전송 활성화

```bash
./dmz_webroot_scanner \
  --watch-dir /var/www/html \
  --scan \
  --kafka-enabled \
  --kafka-brokers broker1:9092,broker2:9092 \
  --kafka-topic dmz.scan.findings \
  --kafka-client-id dmz_scanner \
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
  client_id: dmz_webroot_scanner
  tls: false
  sasl_enabled: false
  username: ""
  password_env: ""
  mask_sensitive: true
```

실행 예시:

```bash
nginx -T 2>&1 | ./dmz_webroot_scanner --config sample_config.yaml
```

CLI로 명시한 값은 설정 파일 값보다 우선하는 방식으로 사용하는 것이 맞습니다.

---

## JSON 리포트 구조

최상위 구조 예시:

```json
{
  "report_version": "1.0",
  "generated_at": "2026-03-20T10:00:00+09:00",
  "scan_started_at": "2026-03-20T09:59:58+09:00",
  "host": "web01",
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

리포트에는 스캔 시작 시각(`scan_started_at`)이 포함되며, 실행 설정(`config`)과 활성 룰(`active_rules`)도 함께 남습니다. 

---

## Streamlit 리포트 파서 실행 예시

```bash
cd streamlit_app
streamlit run Home.py
```

또는 프로젝트 루트 기준:

```bash
streamlit run streamlit_app/Home.py
```

JSON 결과 파일을 업로드하면:

* 리포트 기본 정보
* scan 시작 시각
* roots / findings / config
* 상세 해석 결과

를 UI로 확인할 수 있습니다.

---

## 운영 권장사항

* 기본적으로 `--newer-than-h`를 사용해 최근 변경 파일 위주로 점검
* `--max-depth`로 깊이를 제한
* 캐시, 빌드 산출물, 정적 라이브러리 경로는 `--exclude` 적극 활용
* `--hash`는 증적 확보가 필요한 경우에만 사용
* 콘텐츠/PII 스캔은 대상 확장자를 좁게 지정하여 운영 영향 최소화
* Apache는 자동 수집 누락 가능성이 있으므로 `--watch-dir` 병행 권장 

---

## 한계

* MIME sniff는 샘플 바이트 기반이므로 완전하지 않음
* Apache `DocumentRoot` 추출은 입력 덤프 형식에 영향을 받음
* 콘텐츠/PII 스캔은 정규식/패턴 기반이므로 오탐·미탐 가능
* 대규모 경로 전수 스캔 시 워커 수와 스캔 옵션 조정 필요
* 저장소 내 버전 표기(`main.go`)와 변경이력(`CHANGES.md`)은 현재 함께 정리하는 것이 필요함 


