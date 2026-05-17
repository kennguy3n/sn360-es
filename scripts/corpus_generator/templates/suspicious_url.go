package templates

import (
	"fmt"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// SuspiciousURL generates emails that embed a redirector / shortener
// / freshly-registered link inconsistent with the visible anchor text.
type SuspiciousURL struct{}

// NewSuspiciousURL returns a fresh generator.
func NewSuspiciousURL() *SuspiciousURL { return &SuspiciousURL{} }

// Category implements Generator.
func (g *SuspiciousURL) Category() constant.Category {
	return constant.CategorySuspiciousURL
}

// Generate implements Generator.
func (g *SuspiciousURL) Generate(opts Options) Result {
	pool := localePool(opts.Locale)
	if !opts.IsThreat {
		body := pool.body([]string{
			pool.t("Here's the quarterly report we discussed earlier.",
				"นี่คือรายงานรายไตรมาสที่เราคุยกันก่อนหน้านี้",
				"先ほどお話しした四半期レポートです",
				"앞서 말씀드린 분기 보고서입니다",
				"这是我们之前讨论的季度报告",
				"Đây là báo cáo quý chúng ta đã thảo luận"),
			"https://docs.acme.example/reports/q3-2025.pdf",
		})
		return Result{
			Payload: Payload{
				From:        emailAddr("partner", "trusted-vendor.com"),
				FromDisplay: "Trusted Vendor",
				To:          recipient(opts),
				Subject:     pool.t("Q3 report", "รายงานไตรมาสที่ 3", "Q3レポート", "Q3 보고서", "Q3 报告", "Báo cáo Q3"),
				BodyText:    body,
				Headers:     map[string]string{"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
			},
			AttackType:      "Legitimate document share",
			Description:     "Vendor sending an internal documentation link — clean URL, no rewrite required.",
			ExpectedSignals: []string{"AUTH_PASS", "KNOWN_VENDOR"},
		}
	}

	anchor := pool.t("View Invoice", "ดูใบแจ้งหนี้", "請求書を確認", "송장 보기", "查看发票", "Xem hóa đơn")
	href := suspiciousLoginURL(opts.Rand, opts.Difficulty)
	if opts.Difficulty == LevelEasy {
		href = "http://bit.ly/" + fmt.Sprintf("3%07x", opts.Rand.Uint32()&0x0fffffff)
	}

	bodyText := strings.Join([]string{
		pool.t("Please review the attached invoice using the link below.",
			"กรุณาตรวจสอบใบแจ้งหนี้ผ่านลิงก์ด้านล่าง",
			"以下のリンクから請求書を確認してください",
			"아래 링크를 통해 송장을 확인해 주세요",
			"请通过下面的链接查看发票",
			"Vui lòng xem hóa đơn qua liên kết bên dưới"),
		fmt.Sprintf("%s: %s", anchor, href),
	}, "\n\n")

	bodyHTML := fmt.Sprintf(
		`<p>%s</p><p><a href="%s">%s</a></p>`,
		pool.t("Please review the attached invoice.", "กรุณาตรวจสอบใบแจ้งหนี้", "請求書をご確認ください", "송장을 확인해 주세요", "请查看发票", "Vui lòng xem hóa đơn"),
		href, anchor,
	)

	signals := []string{"URL_DISPLAY_MISMATCH", "SHORTENED_OR_REDIRECTOR_URL"}
	if opts.Difficulty == LevelHard {
		signals = append(signals, "FRESHLY_REGISTERED_DOMAIN")
	}

	return Result{
		Payload: Payload{
			From:        randomFreemailSender(opts.Rand, "billing"),
			FromDisplay: "Accounts Payable",
			To:          recipient(opts),
			Subject:     pool.t("Invoice #INV-9821 due", "ใบแจ้งหนี้ INV-9821", "請求書 INV-9821", "송장 INV-9821", "发票 INV-9821", "Hóa đơn INV-9821"),
			BodyText:    bodyText,
			BodyHTML:    bodyHTML,
			Headers:     map[string]string{"Authentication-Results": "spf=none dkim=none dmarc=none"},
		},
		AttackType:      "Suspicious URL with display mismatch",
		Description:     "Email body links to a shortener / freshly-registered domain whose anchor text claims to be a brand portal.",
		ExpectedSignals: signals,
	}
}
