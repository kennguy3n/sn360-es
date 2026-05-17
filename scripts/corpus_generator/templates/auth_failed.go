package templates

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// AuthFailed generates emails whose Authentication-Results header
// shows SPF/DKIM/DMARC failures — relays from compromised hosts,
// poorly-configured ESPs, or outright spoofing.
type AuthFailed struct{}

// NewAuthFailed returns a fresh generator.
func NewAuthFailed() *AuthFailed { return &AuthFailed{} }

// Category implements Generator.
func (g *AuthFailed) Category() constant.Category {
	return constant.CategoryAuthFailed
}

// Generate implements Generator.
func (g *AuthFailed) Generate(opts Options) Result {
	pool := localePool(opts.Locale)

	if !opts.IsThreat {
		// Benign — partner whose ESP has a temporary DKIM mis-config.
		return Result{
			Payload: Payload{
				From:        emailAddr("notifications", "partner.example"),
				FromDisplay: "Partner Notifications",
				To:          recipient(opts),
				Subject:     pool.t("Weekly status digest", "สรุปสถานะรายสัปดาห์", "週次ステータスダイジェスト", "주간 상태 다이제스트", "每周状态摘要", "Tổng hợp trạng thái hàng tuần"),
				BodyText:    pool.t("This is a routine status email. No action required.", "อีเมลสรุปสถานะปกติ ไม่ต้องดำเนินการ", "通常の状態通知メールです、対応不要です", "정기 상태 메일입니다, 별도 조치 불필요", "例行状态邮件，无需操作", "Email trạng thái định kỳ, không cần xử lý"),
				Headers: map[string]string{
					"Authentication-Results": "spf=pass dkim=temperror dmarc=pass",
				},
			},
			AttackType:      "ESP transient DKIM tempfail",
			Description:     "Authenticated partner sender with a transient DKIM tempfail — should not be flagged as a spoof.",
			ExpectedSignals: []string{"AUTH_TEMPFAIL", "KNOWN_PARTNER"},
		}
	}

	spoofedFrom := emailAddr("ceo", opts.Tenant)
	relayHost := fmt.Sprintf("relay-%d.suspicious-host.example", opts.Index%500)

	body := pool.body([]string{
		pool.t("Are you available? I need a quick favour while I'm in a meeting.",
			"ว่างไหม ฉันต้องการให้ช่วยเล็กน้อย",
			"少し手伝ってもらえますか？会議中です",
			"잠깐 도와줄 수 있어요? 회의 중입니다",
			"在吗？我开会中需要帮忙",
			"Bạn rảnh không? Tôi đang họp và cần giúp một việc"),
	})

	return Result{
		Payload: Payload{
			From:        spoofedFrom,
			FromDisplay: "Acme CEO",
			To:          recipient(opts),
			Subject:     pool.t("Quick favor", "ขอความช่วยเหลือ", "お願いがあります", "부탁이 있어요", "需要帮个忙", "Cần nhờ một việc"),
			BodyText:    body,
			Headers: map[string]string{
				"Received":               fmt.Sprintf("from %s ([203.0.113.%d])", relayHost, opts.Rand.Intn(255)),
				"Authentication-Results": "spf=fail dkim=fail dmarc=fail",
			},
		},
		AttackType:      "SPF/DKIM/DMARC failed spoof",
		Description:     "Header from-address spoofs an internal user, but SPF/DKIM/DMARC all fail — classic direct spoof.",
		ExpectedSignals: []string{"AUTH_FAIL", "SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL", "EXTERNAL_RELAY"},
	}
}
