package root

// RootSource: 웹루트의 출처를 나타내는 상수
type RootSource string

const (
	SourceNginxRoot  RootSource = "nginx.root"          // Nginx root 디렉토리
	SourceNginxAlias RootSource = "nginx.alias"         // Nginx alias 디렉토리
	SourceApacheDR   RootSource = "apache.documentroot" // Apache DocumentRoot
	SourceManual     RootSource = "manual"              // 사용자가 수동 지정
)

// RootEntry: 단일 예단위로 스캔할 웹루트 디렉토리 정보
type RootEntry struct {
	Path        string     `json:"path"`                   // 디렉터리 경로
	RealPath    string     `json:"real_path,omitempty"`    // 심볼릭 해석 후 실제 경로
	Source      RootSource `json:"source"`                 // 디렉터리 출처
	ContextHint string     `json:"context_hint,omitempty"` // 추가 정보
}
