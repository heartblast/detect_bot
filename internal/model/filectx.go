package model

import (
	"time"

	"dmz_webroot_scanner/internal/root"
)

// FileCtx: 파일 스캐닝 동간 수집된 파일 메타데이터를 저장하는 구조체
type FileCtx struct {
	Path       string          // 파일의 절대경로
	RealPath   string          // 심볼릭 해석 후 실제 경로
	RootPath   string          // 스캔되는 단원의 웹루트 경로
	RootSource root.RootSource // 웹루트 소스

	Size    int64     // 파일 크기 (바이트)
	ModTime time.Time // 파일 마지막 수정 시간
	Perm    string    // 파일 권한
	Ext     string    // 파일 확장자
	Mime    string    // MIME 타입

	// 콘텐츠 분석용 필드 (민감정보 패턴 탐지 등에 사용)
	ContentSample      string // 파일 본문 샘플 (전체가 아닌 제한된 부분만)
	ContentSampleBytes int    // 실제로 읽혀진 바이트 수
	ContentTruncated   bool   // 샘플이 잘렸는지 여부 (파일이 ContentSampleBytes보다 크면 true)
}
