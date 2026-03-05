package root

import (
	"path/filepath"
	"sort"
	"strings"
)

// NormalizeRoots: 수집된 웹루트 디렉터리 목록을 정규화함
// 동작: 중복 제거, 경로 정리, symlink 해석, 알파벳순 정렬
// in: 입력 RootEntry 배열
// 반환: 정규화되고 정렬된 RootEntry 배열
func NormalizeRoots(in []RootEntry) []RootEntry {
	// seen: 이미 나타난 디렉터리를 추적 (중복 제거)
	seen := map[string]RootEntry{}
	for _, r := range in {
		// 경로 정리: 공백 제거, 끝에 있는 세미콜론 제거
		p := strings.TrimSpace(r.Path)
		if p == "" {
			continue
		}
		p = strings.TrimRight(p, ";")
		// 따옴표 제거 (Nginx/Apache 출력에 있을 수 있음)
		p = strings.Trim(p, `"'`)
		// 경로 정규화: 중복 슬래시 및 백슬래시 제거
		p = filepath.Clean(p)

		// symlink 해석하여 실제 경로 찾기
		real := ""
		if rp, err := filepath.EvalSymlinks(p); err == nil {
			real = rp
		}
		// 중복 판단: symlink 해석된 경로를 키로 사용
		key := p
		if real != "" {
			key = real // symlink 해석된 결과를 키로 설정
		}

		// 이미 나타난 디렉터리면 건너뛰기
		if existing, ok := seen[key]; ok {
			// 기존 항목에 문맥 정보가 없으면 새것으로 대체
			if existing.ContextHint == "" && r.ContextHint != "" {
				existing.ContextHint = r.ContextHint
				seen[key] = existing
			}
			continue // 중복이므로 스킵
		}
		// 디렉터리 정보 저장
		r.Path = p
		r.RealPath = real
		seen[key] = r
	}

	// 나타난 디렉터리들을 슬라이스로 변환
	out := make([]RootEntry, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	// 경로별로 알파벳 정렬
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
