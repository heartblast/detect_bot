package report

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/heartblast/detect_bot/internal/config"

	"github.com/twmb/franz-go/pkg/kgo"
)

// KafkaEvent: 간단한 스캔 이벤트 스키마
// 필요한 필드를 추가하거나 수정하여 SIEM/Flink 연계에 활용 가능
type KafkaEvent struct {
	Host        string `json:"host"`
	GeneratedAt string `json:"generated_at"`
	RootsCount  int    `json:"roots_count"`
	Findings    []struct {
		Path     string   `json:"path"`
		Severity string   `json:"severity,omitempty"`
		Reasons  []string `json:"reasons,omitempty"`
	} `json:"findings,omitempty"`
}

// makeEvents: 리포트에서 Kafka로 전송할 이벤트 목록을 생성
func (rep *Report) makeEvents(maskSensitive bool) []KafkaEvent {
	e := KafkaEvent{
		Host:        rep.Host.Hostname,
		GeneratedAt: rep.GeneratedAt,
		RootsCount:  rep.Stats.RootsCount,
	}
	if e.Host == "" || e.Host == "unknown" {
		e.Host = rep.Host.PrimaryIP
	}
	for _, f := range rep.Findings {
		item := struct {
			Path     string   `json:"path"`
			Severity string   `json:"severity,omitempty"`
			Reasons  []string `json:"reasons,omitempty"`
		}{
			Path:     f.Path,
			Severity: f.Severity,
			Reasons:  f.Reasons,
		}
		if maskSensitive {
			// 간단히 경로 마스킹(파일명 제외)
			idx := strings.LastIndex(item.Path, "/")
			if idx != -1 {
				item.Path = "[MASKED]" + item.Path[idx:]
			} else {
				item.Path = "[MASKED]"
			}
		}
		e.Findings = append(e.Findings, item)
	}
	return []KafkaEvent{e}
}

// SendToKafka: Report를 요약하여 Kafka에 전송
// 실패해도 호출자는 경고만 출력하고 스캔을 중단하지 않아야 함
func SendToKafka(rep Report, cfg config.KafkaConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if len(cfg.Brokers) == 0 || cfg.Topic == "" {
		return fmt.Errorf("kafka brokers or topic not configured")
	}
	// 클라이언트 구성
	opts := []kgo.Opt{kgo.SeedBrokers(cfg.Brokers...)}
	if cfg.ClientID != "" {
		opts = append(opts, kgo.ClientID(cfg.ClientID))
	}
	if cfg.TLSEnabled {
		opts = append(opts, kgo.DialTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	if cfg.SASLEnabled {
		// SASL support stub: currently not implemented, just log warning
		pwd := os.Getenv(cfg.PasswordEnv)
		fmt.Fprintf(os.Stderr, "INFO: SASL enabled but not implemented (user=%s, pwdenv=%s)\n", cfg.Username, cfg.PasswordEnv)
		_ = pwd
	}
	client, err := kgo.NewClient(opts...)
	if err != nil {
		return err
	}
	defer client.Close()

	events := rep.makeEvents(cfg.MaskSensitive)
	for _, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		req := &kgo.Record{Topic: cfg.Topic, Value: b}
		if err := client.ProduceSync(context.Background(), req).FirstErr(); err != nil {
			return err
		}
	}
	return nil
}
