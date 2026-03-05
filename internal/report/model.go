package report

import "dmz_webroot_scanner/internal/root"

// Finding: 의심되는 단일 파일의 검사 결과를 나타내는 구조체
type Finding struct {
	Path                 string   `json:"path"`                             // 의심 파일의 경로
	RealPath             string   `json:"real_path,omitempty"`              // 심볼릭 해석 후 실제 경로
	Size                 int64    `json:"size_bytes"`                       // 파일 크기
	ModTime              string   `json:"mod_time"`                         // 마지막 수정 시간
	Perm                 string   `json:"perm"`                             // 파일 권한
	Ext                  string   `json:"ext"`                              // 파일 확장자
	MimeSniff            string   `json:"mime_sniff"`                       // 스니프된 MIME 타입
	Reasons              []string `json:"reasons"`                          // 의심으로 판단된 규칙 이름들
	SHA256               string   `json:"sha256,omitempty"`                 // SHA256 해시값
	URLExposureHeuristic string   `json:"url_exposure_heuristic,omitempty"` // URL 노출 휴리스틱
	RootMatched          string   `json:"root_matched,omitempty"`           // 매칭된 웹루트 경로
	RootSource           string   `json:"root_source,omitempty"`            // 웹루트 소스
	Severity             string   `json:"severity,omitempty"`               // 오류 중요도
}

// Report: 전체 스캔 결과를 메타데이터와 단일들로 저장하는 최상위 구조체
type Report struct {
	ReportVersion string           `json:"report_version,omitempty"` // 리포트 버전
	GeneratedAt   string           `json:"generated_at"`             // 리포트 생성 시간
	Host          string           `json:"host,omitempty"`           // 스캔 실행 호스트명
	Inputs        []string         `json:"inputs"`                   // 입력 소스 목록
	Roots         []root.RootEntry `json:"roots"`                    // 추출된 웹루트 목록
	Findings      []Finding        `json:"findings"`                 // 검출된 의심 파일 목록
	Stats         struct {         // 스캔 통계
		RootsCount    int `json:"roots_count"`    // 추출된 웹루트 총 개수
		ScannedFiles  int `json:"scanned_files"`  // 스캔된 파일 총 개수
		FindingsCount int `json:"findings_count"` // 검촉된 의심 파일 수
	} `json:"stats"`
}
