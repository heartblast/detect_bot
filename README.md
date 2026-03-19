DMZ 구간 웹서버의 웹서빙 경로(root/alias/DocumentRoot) 를 웹서버 설정 “덤프 출력”에서 자동 수집하고, 해당 경로를 스캔하여 용도 부적합 파일(스테이징/반출 징후, 웹쉘/스크립트/아카이브 등) 을 룰 기반으로 탐지한 뒤 표준 JSON 보고서로 산출하는 경량 도구입니다.

**현재 버전: v1.1.2**

실행 시 `NICE DetectBot` ASCII 배너가 stderr로 출력되며, 바로 아래에 버전 정보(예: `Version: v1.1.2`)가 표시됩니다. 배너는 `internal/banner/nice_detectbot.txt`에 템플릿으로 보관되며, Go `embed`로 컴파일 시 바이너리에 포함되어 별도 파일 의존성이 없습니다.

> 목적은 침해 지원이 아닌 통제/탐지/감사입니다.  
> MIME 판별은 `net/http.DetectContentType`(최대 512B sniff) 기반이라 100% 정확하지 않습니다.

---

## 주요 특징

- 덤프 기반 웹서빙 경로 자동 추출
  - Nginx: `nginx -T` 출력에서 `root`, `alias` 파싱
  - Apache: `apachectl -S` 출력에서 `DocumentRoot`가 포함된 경우 파싱(환경에 따라 제한)
  - 누락 보완: `--watch-dir`로 경로 수동 추가 가능

- 룰 엔진 구조(확장성)
  - Allowlist(확장자/MIME), HighRisk 확장자, Large file, Ext–MIME mismatch 등 룰을 모듈로 분리
  - 룰 추가/수정 시 스캔 엔진 변경 최소화

- 민감정보 콘텐츠 분석(선택적)
  - YAML/JSON/ENV 등 텍스트 파일의 본문 샘플링 스캔
  - 연결 문자열(JDBC, Redis, MongoDB, PostgreSQL, LDAP 등), 자격증명(password, token, api_key 등), 비공개 키 탐지
  - 조합 탐지: 연결정보+비밀번호, S3+access_key+secret_key 등 고위험 조합
  - 민감정보 원문 미저장, 마스킹된 증거만 리포트에 기록

- 개인정보(PII) 탐지(선택적)
  - 텍스트 파일 본문에서 주민등록번호, 외국인등록번호, 여권번호, 운전면허번호, 카드번호, 계좌번호, 휴대전화번호, 이메일 패턴 탐지
  - 형식 검증(Luhn 알고리즘, 날짜 유효성 등) 및 문맥 키워드 분석으로 오탐 방지
  - 신뢰도 기반 판정: validated(검증 통과), suspected(문맥 근거), weak_match(패턴 일치만)
  - 민감정보 원문 미저장, 마스킹된 샘플만 기록

- 운영 친화 옵션
  - `--newer-than-h`, `--max-depth`, `--exclude`로 운영 영향 최소화
  - `--hash`는 필요 시만(부하 증가 가능)

- 표준 JSON 리포트
  - roots / findings / stats 포함
  - `scan_started_at` 필드에 스캔 시작 시각(RFC3339) 포함
  - findings에는 reasons(탐지 사유)와 severity(위험도) 포함

---

## 설치/빌드

### 빌드(로컬)
```bash
go build -o dmz_webroot_scanner ./cmd/dmz_webroot_scanner
````

### 크로스 빌드(Windows → Linux 예시)

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -trimpath -ldflags "-s -w" -o dist/dmz_webroot_scanner ./cmd/dmz_webroot_scanner
```

---

## 사용 예시(운영 권장)

### 1) Nginx 덤프 파이프 입력 + 스캔(권장)

```bash
nginx -T 2>&1 | ./dmz_webroot_scanner \
  --nginx-dump - \
  --scan \
  --newer-than-h 24 \
  --max-depth 10 \
  --exclude /var/cache \
  --out /var/log/dmz_webroot_scanner/report-$(date +%F).json
```

### 2) Apache 덤프 파이프 입력 + 스캔

```bash
apachectl -S 2>&1 | ./dmz_webroot_scanner \
  --apache-dump - \
  --scan \
  --newer-than-h 24 \
  --max-depth 10 \
  --out /var/log/dmz_webroot_scanner/report-$(date +%F).json
```

> Apache는 `apachectl -S` 출력에 `DocumentRoot`가 보이지 않으면 roots가 비어 있을 수 있습니다.
> 이 경우 `--watch-dir`로 실제 웹루트/업로드 경로를 함께 지정하세요.

### 3) 덤프 + 수동 감시 경로 보강(실무 권장)

```bash
nginx -T 2>&1 | ./dmz_webroot_scanner \
  --nginx-dump - \
  --scan \
  --watch-dir /var/www/html \
  --watch-dir /data/webroot \
  --newer-than-h 24 \
  --max-depth 10 \
  --exclude /var/www/html/cache \
  --out /var/log/dmz_webroot_scanner/report-$(date +%F).json
```

### 4) 표준출력으로 출력 + jq로 빠르게 확인

```bash
nginx -T 2>&1 | ./dmz_webroot_scanner --nginx-dump - --scan --out - \
  | jq '.findings[] | {path, size_bytes, mime_sniff, reasons, severity}'
```

### 5) 해시 포함(증거 보존/격리 전 확인용)

```bash
nginx -T 2>&1 | ./dmz_webroot_scanner \
  --nginx-dump - \
  --scan \
  --hash --max-size-mb 100 \
  --out /var/log/dmz_webroot_scanner/report-$(date +%F)-hash.json
```

### 6) 콘텐츠 스캔 활성화(YAML/JSON/ENV 등에서 민감정보 탐지)

```bash
nginx -T 2>&1 | ./dmz_webroot_scanner \
  --nginx-dump - \
  --scan \
  --content-scan \
  --content-max-bytes 65536 \
  --content-max-size-kb 1024 \
  --content-ext .yaml --content-ext .yml --content-ext .json --content-ext .env \
  --out /var/log/dmz_webroot_scanner/report-$(date +%F)-content.json
```

### 7) PII 탐지 활성화(텍스트 파일에서 개인정보 패턴 탐지)

```bash
nginx -T 2>&1 | ./dmz_webroot_scanner \
  --nginx-dump - \
  --scan \
  --pii-scan \
  --pii-max-bytes 65536 \
  --pii-max-size-kb 256 \
  --pii-ext .yaml --pii-ext .json --pii-ext .txt --pii-ext .log \
  --pii-mask \
  --pii-store-sample \
  --pii-context-keywords \
  --out /var/log/dmz_webroot_scanner/report-$(date +%F)-pii.json
```

---

## 추가 기능 소개

### 프리셋
반복적으로 같은 조합을 사용하는 운영자를 위해 내부에 다섯 가지 프리셋이 정의되어 있습니다:

* `safe` : 운영 영향 최소화 중심 (짧은 깊이, 콘텐츠 스캔 비활성)
* `balanced` : README 권장 설정과 유사한 기본 모드
* `deep` : 탐색 범위 및 콘텐츠 샘플링을 강화
* `handover` : 인수인계 시점 점검용 (깊이 제한, 콘텐츠 검사 제외)
* `offboarding` : 담당자 교체/퇴직 전 점검용 (광범위 + 콘텐츠 검사)

프리셋은 `--preset <name>`으로 지정하며, CLI가 명시적으로 설정한 값은 항상 우선합니다.

### 설정 파일 지원
CLI 대신 YAML 또는 JSON 파일을 통해 실행 구성을 지정할 수 있습니다. 예시:

```yaml
# scan_config.yaml
preset: balanced
server_type: nginx
nginx_dump: -
scan: true
newer_than_h: 24
max_depth: 12
exclude:
  - /var/cache
workers: 4
content_scan: true
kafka:
  enabled: true
  brokers:
    - broker1:9092
    - broker2:9092
  topic: dmz.scan.findings
  mask_sensitive: true
rules:
  enable:
    - high_risk_ext
  disable:
    - large_file
```

JSON 형태도 동일 스키마를 지원합니다. `--config <path>` 플래그로 파일을 지정하고, CLI 옵션은 파일의 설정을 덮어씁니다.

### 서버 유형 & 입력 방식
`--server-type nginx|apache|manual`을 통해 유형을 명시할 수 있으며,
기본값(`--server-type` 미지정)도 기존 방식과 호환됩니다. 잘못된 조합을 사용하면 에러가 발생합니다.

### 룰 세부 제어
`--enable-rules`/`--disable-rules`로 개별 룰을 켜거나 끌 수 있습니다. 컴마 구분 또는 여러 번 반복 가능합니다.

### Kafka 연계
탐지 결과를 요약된 이벤트 형태로 Kafka에 전송할 수 있습니다.
옵션 목록은 다음과 같습니다.

* `--kafka-enabled` : 전송 활성화
* `--kafka-brokers` : 브로커 목록
* `--kafka-topic` : 전송 토픽
* `--kafka-client-id` : 클라이언트 ID
* `--kafka-tls` : TLS 사용 여부
* `--kafka-sasl-enabled` : SASL 인증 사용 (현재 스텁)
* `--kafka-username` : SASL 사용자
* `--kafka-password-env` : 비밀번호가 저장된 환경변수 이름
* `--kafka-mask-sensitive` : 민감정보 마스킹

Kafka 전송 실패는 전체 스캔에 영향을 주지 않으며, 로컬 JSON 리포트는 항상 생성됩니다.

### Streamlit UI (리포트 파서)
`streamlit_app/`에 포함된 Streamlit 페이지에서는 JSON 리포트를 업로드하면 스캔 요약과 탐지 결과를 시각화합니다. 최근 추가된 `scan_started_at` 필드도 상단 메타 정보에 표시됩니다.

### Kafka 이벤트 스키마 예시
```json
{
  "host": "web01.example.com",
  "generated_at": "2026-03-12T10:15:30Z",
  "roots_count": 3,
  "findings": [
    {"path": "/var/www/html/config.php", "severity": "high", "reasons": ["high_risk_extension"]},
    {"path": "/var/www/html/.env", "severity": "critical", "reasons": ["secret_patterns"]}
  ]
}
```

이러한 간략화된 이벤트는 SIEM/Flink 등으로 스트리밍되어 추가 분석에 활용할 수 있습니다.

### PII 탐지
텍스트 기반 파일에서 개인정보 유출위험 패턴을 탐지합니다. 탐지 대상은 주민등록번호, 외국인등록번호, 여권번호, 운전면허번호, 카드번호, 계좌번호, 휴대전화번호, 이메일, 생년월일입니다.

* 검증 로직: 카드번호(Luhn), 이메일 형식, 생년월일 날짜 유효성 등
* 문맥 보강: "주민", "email", "card" 등 키워드 주변 탐지 시 신뢰도 상향
* 판정 상태: `validated`(검증 통과), `suspected`(문맥 근거), `weak_match`(패턴 일치만)
* 마스킹: 주민등록번호 `901010-1******`, 카드번호 `1234-****-****-5678` 등
* 옵션: `--pii-scan` 활성화, `--pii-ext` 대상 확장자, `--pii-mask` 마스킹, `--pii-context-keywords` 문맥 분석

---

## 옵션 요약

* 입력

  * `--server-type nginx|apache|manual` : 웹서버 유형을 명시 (auto-detect 가능)
  * `--config <path>` : YAML/JSON 설정 파일 (CLI 값이 우선)
  * `--preset <name>` : 프리셋 선택 (safe, balanced, deep, handover, offboarding)
  * `--nginx-dump <path|->` : nginx -T 덤프 파일 또는 `-`(stdin)
  * `--apache-dump <path|->` : apachectl -S 덤프 파일 또는 `-`(stdin)

* 스캔/범위

  * `--scan` : 루트 스캔 수행
  * `--watch-dir <path>` : 수동 감시 경로 추가(반복)
  * `--exclude <prefix>` : 제외 경로 prefix(반복)
  * `--max-depth <n>` : 재귀 깊이(기본 12)
  * `--newer-than-h <h>` : 최근 N시간 수정 파일만 평가(0=비활성)

* 정책(allowlist) 및 룰 제어

  * `--allow-mime-prefix <prefix>` : 허용 MIME prefix(반복)
  * `--allow-ext <.ext>` : 허용 확장자(반복)
  * `--enable-rules <names>` : 추가 활성화할 룰(컴마 또는 반복)
  * `--disable-rules <names>` : 비활성화할 룰
  * (미지정 시 DMZ 정적 웹 서버 기준 기본 allowlist + 기본 룰셋)

* 부하/성능

  * `--workers <n>` : 스캔 워커 수(기본 4)
  * `--hash` : SHA-256 계산(부하 증가 가능)
  * `--max-size-mb <n>` : 해시/MIME sniff를 위한 최대 읽기 크기(MB)
  * `--follow-symlink` : 심볼릭 링크 추적(기본 false, DMZ 점검 비권장)

* 콘텐츠 분석(민감정보 탐지)

  * `--content-scan` : 파일 내용에서 민감정보 패턴 탐지 활성화(기본 false)
  * `--content-max-bytes <n>` : 파일별 콘텐츠 샘플 최대 읽기 바이트(기본 65536)
  * `--content-max-size-kb <n>` : 콘텐츠 스캔 대상 파일 최대 크기(KB, 기본 1024)
  * `--content-ext <.ext>` : 콘텐츠 스캔 대상 확장자 지정(반복, 기본: .yaml .yml .json .xml .properties .conf .env .ini .txt .config .cfg .toml)

* PII 분석(개인정보 탐지)

  * `--pii-scan` : 파일 내용에서 개인정보 패턴 탐지 활성화(기본 false)
  * `--pii-max-bytes <n>` : 파일별 PII 샘플 최대 읽기 바이트(기본 65536)
  * `--pii-max-size-kb <n>` : PII 스캔 대상 파일 최대 크기(KB, 기본 256)
  * `--pii-max-matches <n>` : 규칙별 최대 저장 샘플 수(기본 5)
  * `--pii-ext <.ext>` : PII 스캔 대상 확장자 지정(반복, 기본: .yaml .yml .json .xml .properties .conf .env .ini .txt .log .csv .tsv)
  * `--pii-mask` : PII 값 마스킹 적용(기본 false)
  * `--pii-store-sample` : 마스킹된 샘플 저장(기본 false)
  * `--pii-context-keywords` : 문맥 키워드 분석 활성화(기본 false)

* 출력

  * `--out <path|->` : JSON 출력 파일 또는 `-`(stdout)

---

## 탐지 룰(기본)

### 메타데이터 기반 탐지
* `mime_not_in_allowlist` : MIME allowlist 위반
* `ext_not_in_allowlist` : 확장자 allowlist 위반
* `high_risk_extension` : 고위험 확장자(아카이브/덤프/스크립트/실행파일 등)
* `large_file_in_web_path` : 웹경로 대용량 파일(기본 50MB)
* `ext_mime_mismatch_image` : 이미지 확장자 ↔ MIME 불일치
* `ext_mime_mismatch_archive` : html/css/js ↔ zip MIME 불일치

### 콘텐츠 기반 민감정보 탐지 (--content-scan 활성화 시)

**연결 문자열 및 URI**
* `connection_jdbc_url` : JDBC 데이터베이스 연결 문자열 (critical)
* `connection_redis_uri` : Redis 연결 URI (high)
* `connection_mongodb_uri` : MongoDB 연결 문자열 (critical)
* `connection_postgresql_uri` : PostgreSQL 연결 문자열 (critical)
* `connection_mysql_uri` : MySQL 연결 문자열 (critical)
* `connection_ldap_uri` : LDAP/LDAPS URI (high)
* `connection_smtp_uri` : SMTP 연결 정보 (high)
* `connection_s3_endpoint` : S3/MinIO endpoint (high)

**자격 증명**
* `credential_password` : password 키 매칭 (critical)
* `credential_username` : username 키 매칭 (medium)
* `credential_db_user` : db_user 키 매칭 (medium)
* `credential_db_password` : db_password 키 매칭 (critical)
* `credential_bind_dn` : LDAP bind_dn 키 (high)
* `credential_bind_password` : LDAP bind_password 키 (critical)
* `credential_access_key` : AWS/S3 access_key (critical)
* `credential_secret_key` : AWS/S3 secret_key (critical)
* `credential_api_key` : API 키 (critical)
* `credential_client_secret` : OAuth client_secret (critical)
* `credential_token` : 토큰 정보 (high)

**비공개 키 자료**
* `private_key_rsa` : RSA 비공개 키 블록 (critical)
* `private_key_openssh` : OpenSSH 비공개 키 블록 (critical)
* `private_key_generic` : 일반 비공개 키 블록 (critical)
* `private_key_ec` : EC 비공개 키 블록 (critical)
* `private_key_pgp` : PGP 비공개 키 블록 (critical)

**내부 엔드포인트**
* `internal_endpoint_private_ip` : 사설 IP 대역(10.x, 172.16-31.x, 192.168.x) (medium)
* `internal_endpoint_domain` : 내부 도메인(.internal, .local, .corp, .intra) (medium)

### PII 기반 개인정보 탐지 (--pii-scan 활성화 시)

**주민등록번호 관련**
* `resident_registration_number` : 주민등록번호 패턴 (critical, validated/suspected/weak_match)

**외국인등록번호 관련**
* `foreigner_registration_number` : 외국인등록번호 패턴 (critical, validated/suspected/weak_match)

**여권번호 관련**
* `passport_number` : 여권번호 패턴 (high, suspected/weak_match)

**운전면허번호 관련**
* `drivers_license` : 운전면허번호 패턴 (high, suspected/weak_match)

**카드번호 관련**
* `credit_card` : 신용카드번호 패턴 (critical, validated/suspected/weak_match)

**계좌번호 관련**
* `bank_account` : 은행계좌번호 패턴 (high, suspected/weak_match)

**휴대전화번호 관련**
* `mobile_phone` : 휴대전화번호 패턴 (medium, validated/suspected/weak_match)

**이메일 관련**
* `email` : 이메일 주소 패턴 (medium, validated/suspected/weak_match)

**위험한 조합 탐지 (높은 우선순위)**
* `combo_jdbc_with_credentials` : JDBC URL + 비밀번호 (critical)
* `combo_datasource_with_credentials` : datasource + username + password (critical)
* `combo_redis_with_password` : Redis 연결 + password (critical)
* `combo_s3_with_keys` : S3/MinIO endpoint + access_key + secret_key (critical)
* `combo_ldap_with_credentials` : LDAP URL + bind_dn + bind_password (critical)

---

## 출력(JSON) 개요

* `roots[]` : 추출된 웹서빙 경로 목록(소스/힌트 포함)
* `findings[]` : 탐지 결과
  * `path`, `size_bytes`, `mod_time`, `perm`, `ext` : 파일 메타정보
  * `mime_sniff` : 스니프된 MIME 타입
  * `reasons[]` : 탐지 규칙 코드 목록
  * `severity` : 최고 위험도 (critical/high/medium/low)
  * `matched_patterns[]` : 탐지된 민감정보 패턴 종류 (--content-scan 또는 --pii-scan 활성화 시)
  * `evidence_masked[]` : 마스킹된 증거 (민감정보/PII 원문 제외, 운영자 이해용)
  * `content_flags` : 콘텐츠 분석 플래그 (e.g. "truncated")
  * `sha256` : SHA256 해시값 (--hash 활성화 시)
* `stats` : 스캔 파일 수, 탐지 건수 등 요약

---

## 파일 구조(개발자용)

* `cmd/dmz_webroot_scanner/main.go` : 엔트리포인트(조립)
* `internal/config/config.go` : CLI 옵션 파싱 및 설정 구조
* `internal/input/` : nginx/apache 덤프 파싱
  * `nginx.go` : Nginx 설정 파싱
  * `apache.go` : Apache 설정 파싱
  * `reader.go` : 덤프 입력 처리
* `internal/root/` : 루트 정규화/중복 제거
  * `types.go` : RootEntry 타입 정의
  * `normalize.go` : 루트 경로 정규화 로직
* `internal/scan/` : 워커풀 스캔 엔진 + 파일 순회
  * `scanner.go` : 메인 스캔 엔진 및 워커풀
  * `sniff.go` : MIME 타입 감지
  * `walk_unix.go` : Unix/Linux 파일 순회(platform build tag)
  * `walk_windows.go` : Windows 파일 순회(platform build tag)
  * `walk_common.go` : 공용 함수(walkItem, depth)
  * `filectx.go` : 파일 컨텍스트 관리
* `internal/rules/` : 탐지 룰 인터페이스 및 내장 룰
  * `rule.go` : Rule 인터페이스 정의
  * `builtin_allowlist.go` : Allowlist 룰
  * `builtin_highrisk.go` : 고위험 확장자 룰
  * `builtin_largefile.go` : 대용량 파일 룰
  * `builtin_mismatch.go` : 확장자-MIME 불일치 룰
  * `builtin_secretpatterns.go` : 민감정보(연결문자열/자격증명/키) 탐지 룰
* `internal/report/` : JSON 리포트 생성 및 출력
  * `model.go` : Report/Finding 스키마
  * `writer.go` : JSON 쓰기 및 포맷팅
* `internal/model/` : 공용 타입(FileCtx) (import cycle 방지)

---

## 운영 권장값(서비스 영향 최소화)

* `--newer-than-h 24` + `--max-depth 8~12` + `--exclude` 적극 활용
* `--hash`는 필요 시에만 사용(부하 증가)
* `--follow-symlink`는 DMZ 점검에서는 기본 비권장

---

## 로드맵

* ✅ 샘플링 기반 PII 탐지(성능 제한 포함) - v1.1 구현 완료
* Apache vhost 설정 파일 파싱/Include 확장(정확도 개선)
* 정책 외부화(YAML): allowlist/exclude/임계치/리스크 스코어
* 민감정보 탐지 룰 YAML/JSON 외부화 (패턴셋 커스터마이징)
* SIEM 연계를 위한 이벤트 스키마 확장/전송 방식 고도화
