DMZ 구간 웹서버의 웹서빙 경로(root/alias/DocumentRoot) 를 웹서버 설정 “덤프 출력”에서 자동 수집하고, 해당 경로를 스캔하여 용도 부적합 파일(스테이징/반출 징후, 웹쉘/스크립트/아카이브 등) 을 룰 기반으로 탐지한 뒤 표준 JSON 보고서로 산출하는 경량 도구입니다.

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

- 운영 친화 옵션
  - `--newer-than-h`, `--max-depth`, `--exclude`로 운영 영향 최소화
  - `--hash`는 필요 시만(부하 증가 가능)

- 표준 JSON 리포트
  - roots / findings / stats 포함
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

---

## 옵션 요약

* 입력

  * `--nginx-dump <path|->` : nginx -T 덤프 파일 또는 `-`(stdin)
  * `--apache-dump <path|->` : apachectl -S 덤프 파일 또는 `-`(stdin)

* 스캔/범위

  * `--scan` : 루트 스캔 수행
  * `--watch-dir <path>` : 수동 감시 경로 추가(반복)
  * `--exclude <prefix>` : 제외 경로 prefix(반복)
  * `--max-depth <n>` : 재귀 깊이(기본 12)
  * `--newer-than-h <h>` : 최근 N시간 수정 파일만 평가(0=비활성)

* 정책(allowlist)

  * `--allow-mime-prefix <prefix>` : 허용 MIME prefix(반복)
  * `--allow-ext <.ext>` : 허용 확장자(반복)
  * (미지정 시 DMZ 정적 웹 서버 기준 기본 allowlist 적용)

* 부하/성능

  * `--workers <n>` : 스캔 워커 수(기본 4)
  * `--hash` : SHA-256 계산(부하 증가 가능)
  * `--max-size-mb <n>` : 해시/MIME sniff를 위한 최대 읽기 크기(MB)
  * `--follow-symlink` : 심볼릭 링크 추적(기본 false, DMZ 점검 비권장)

* 출력

  * `--out <path|->` : JSON 출력 파일 또는 `-`(stdout)

---

## 탐지 룰(기본)

* `mime_not_in_allowlist` : MIME allowlist 위반
* `ext_not_in_allowlist` : 확장자 allowlist 위반
* `high_risk_extension` : 고위험 확장자(아카이브/덤프/스크립트/실행파일 등)
* `large_file_in_web_path` : 웹경로 대용량 파일(기본 50MB)
* `ext_mime_mismatch_image` : 이미지 확장자 ↔ MIME 불일치
* `ext_mime_mismatch_archive` : html/css/js ↔ zip MIME 불일치

---

## 출력(JSON) 개요

* `roots[]` : 추출된 웹서빙 경로 목록(소스/힌트 포함)
* `findings[]` : 탐지 결과(사유 reasons / severity / 파일 메타정보)
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

* Apache vhost 설정 파일 파싱/Include 확장(정확도 개선)
* 정책 외부화(YAML): allowlist/exclude/임계치/리스크 스코어
* 샘플링 기반 PII 탐지(성능 제한 포함)
* SIEM 연계를 위한 이벤트 스키마 확장/전송 방식 고도화
