package templates

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// Newsletter generates bulk marketing / newsletter traffic. Benign
// variants should bypass Tier 0; the rare threat variant is a
// newsletter platform that has been hijacked to push a phishing
// link.
type Newsletter struct{}

// NewNewsletter returns a fresh generator.
func NewNewsletter() *Newsletter { return &Newsletter{} }

// Category implements Generator.
func (g *Newsletter) Category() constant.Category {
	return constant.CategoryNewsletter
}

// Generate implements Generator.
func (g *Newsletter) Generate(opts Options) Result {
	pool := localePool(opts.Locale)
	platforms := []string{"mailchimp.example", "sendgrid.example", "marketo.example", "hubspot.example"}
	platform := platforms[opts.Index%len(platforms)]

	if !opts.IsThreat {
		return Result{
			Payload: Payload{
				From:        emailAddr("newsletter", platform),
				FromDisplay: "Industry Weekly",
				To:          recipient(opts),
				Subject:     pool.t("Industry Weekly — top 5 stories", "ข่าวอุตสาหกรรมประจำสัปดาห์", "業界ウィークリー", "주간 산업 소식", "行业周刊", "Bản tin ngành hàng tuần"),
				BodyText:    pool.t("Top stories this week, curated for you.", "ข่าวเด่นประจำสัปดาห์ที่คัดสรรให้คุณ", "今週の主要記事をお届けします", "이번 주 주요 기사 모음", "本周精选热门资讯", "Tin nổi bật tuần này được tuyển chọn cho bạn"),
				Headers: map[string]string{
					"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
					"List-Unsubscribe":       fmt.Sprintf("<mailto:unsub@%s>", platform),
					"Precedence":             "bulk",
				},
			},
			AttackType:      "Routine bulk newsletter",
			Description:     "Authenticated, unsubscribable bulk mailer — must Tier 0 bypass and classify Informational/Trusted.",
			ExpectedSignals: []string{"BULK_PRECEDENCE", "LIST_UNSUBSCRIBE_PRESENT", "AUTH_PASS"},
		}
	}

	target := suspiciousLoginURL(opts.Rand, opts.Difficulty)
	return Result{
		Payload: Payload{
			From:        emailAddr("offers", platform),
			FromDisplay: "Exclusive Member Offer",
			To:          recipient(opts),
			Subject: pool.t("Account verification needed for newsletter benefits",
				"ต้องยืนยันบัญชีเพื่อรับสิทธิประโยชน์",
				"特典を受け取るためアカウント確認が必要",
				"혜택을 받으려면 계정 확인이 필요합니다",
				"领取会员福利需验证账户",
				"Cần xác minh tài khoản để nhận ưu đãi"),
			BodyText: pool.body([]string{
				pool.t("As a subscriber, please re-verify your work email to unlock this month's premium content.",
					"ในฐานะสมาชิก กรุณายืนยันอีเมลที่ทำงานเพื่อรับเนื้อหาพิเศษ",
					"購読者の方は、特別コンテンツを利用するためメールを再確認してください",
					"구독자께서는 프리미엄 콘텐츠 이용을 위해 메일을 재확인해 주세요",
					"作为订阅用户，请重新验证您的工作邮箱以解锁本月内容",
					"Là người đăng ký, vui lòng xác minh lại email công ty"),
				fmt.Sprintf("Verify: %s", target),
			}),
			Headers: map[string]string{
				"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
				"List-Unsubscribe":       fmt.Sprintf("<mailto:unsub@%s>", platform),
				"Precedence":             "bulk",
			},
		},
		AttackType:      "Hijacked newsletter platform credential harvest",
		Description:     "Newsletter platform pushing a credential-verification link to a lookalike domain — bulk-tier phish.",
		ExpectedSignals: []string{"BULK_PRECEDENCE", "CREDENTIAL_LINK", "EXTERNAL_LOGIN_DOMAIN"},
	}
}
