package templates

import (
	"fmt"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// LikelyPhishing generates emails resembling broad-spectrum phishing
// — credential-grab pages disguised as Microsoft / Google security
// notices, package-delivery prompts, and similar.
type LikelyPhishing struct{}

// NewLikelyPhishing returns a fresh LikelyPhishing generator.
func NewLikelyPhishing() *LikelyPhishing { return &LikelyPhishing{} }

// Category implements Generator.
func (g *LikelyPhishing) Category() constant.Category {
	return constant.CategoryLikelyPhishing
}

// Generate implements Generator.
func (g *LikelyPhishing) Generate(opts Options) Result {
	pool := localePool(opts.Locale)
	display := pick(opts.Rand, []string{
		"Microsoft Account Team", "Google Security", "Apple Support",
		"DHL Express", "FedEx Shipping", "IT Helpdesk", "Office 365 Admin",
	})

	if !opts.IsThreat {
		// Benign look-alike: real internal IT bulletin with no
		// credential prompt or rewritten URL.
		subj := pool.t("Reminder: Quarterly password reset",
			"เตือนเปลี่ยนรหัสผ่านประจำไตรมาส",
			"四半期パスワードリセットのお知らせ",
			"분기별 비밀번호 재설정 알림",
			"季度密码重置提醒",
			"Nhắc nhở đổi mật khẩu định kỳ")
		_ = display
		body := pool.body([]string{
			"As part of our scheduled IT hygiene, please change your password from the company portal at your convenience.",
			"No action is required if you have already rotated credentials this quarter.",
			"Need help? Reply to this thread and the helpdesk will reach out.",
		})
		return Result{
			Payload: Payload{
				From:        emailAddr("itsupport", opts.Tenant),
				FromDisplay: "IT Helpdesk",
				To:          recipient(opts),
				Subject:     subj,
				BodyText:    body,
			},
			AttackType:      "Benign internal IT reminder",
			Description:     "Internal helpdesk bulletin with no credential prompt — should score Trusted/Informational.",
			ExpectedSignals: []string{"INTERNAL_ORIGIN", "NO_EXTERNAL_LINKS"},
		}
	}

	urgency := pool.t("Your account will be suspended in 24 hours",
		"การยืนยันด่วน: บัญชีจะถูกระงับใน 24 ชั่วโมง",
		"アカウントは24時間以内に停止されます",
		"24시간 안에 계정이 일시 중지됩니다",
		"您的帐户将在24小时内被暂停",
		"Tài khoản của bạn sẽ bị tạm ngưng trong 24 giờ")

	link := suspiciousLoginURL(opts.Rand, opts.Difficulty)
	bodyParts := []string{
		urgency,
		pool.t("Please verify your credentials immediately to avoid service interruption.",
			"กรุณายืนยันข้อมูลการเข้าสู่ระบบของคุณทันทีเพื่อหลีกเลี่ยงการระงับบริการ",
			"サービス停止を避けるため、直ちにログイン情報を確認してください",
			"서비스 중단을 방지하려면 즉시 자격 증명을 확인하세요",
			"请立即验证您的凭据以避免服务中断",
			"Vui lòng xác minh thông tin đăng nhập ngay để tránh gián đoạn dịch vụ"),
		fmt.Sprintf("%s: %s", pool.t("Verify", "ยืนยัน", "確認", "확인", "验证", "Xác minh"), link),
	}
	bodyText := strings.Join(bodyParts, "\n\n")

	bodyHTML := fmt.Sprintf(
		`<p>%s</p><p><a href="%s">%s</a></p>`,
		bodyParts[0], link, pool.t("Click here to verify", "คลิกที่นี่เพื่อยืนยัน", "ここをクリックして確認", "여기를 클릭하여 확인", "点击此处验证", "Bấm vào đây để xác minh"),
	)

	signals := []string{"URGENT_TONE", "CREDENTIAL_LINK", "EXTERNAL_LOGIN_DOMAIN"}
	if opts.Difficulty == LevelHard {
		signals = append(signals, "OBFUSCATED_URL")
	}

	return Result{
		Payload: Payload{
			From:        randomFreemailSender(opts.Rand, "support"),
			FromDisplay: display,
			To:          recipient(opts),
			Subject:     urgency,
			BodyText:    bodyText,
			BodyHTML:    bodyHTML,
			Headers: map[string]string{
				"Reply-To":               randomFreemailSender(opts.Rand, "no-reply"),
				"Authentication-Results": "spf=none dkim=none dmarc=none",
			},
		},
		AttackType:      "Credential phishing with urgency + suspicious link",
		Description:     "Phishing email impersonating a major brand and prompting credential entry on an off-brand login domain.",
		ExpectedSignals: signals,
	}
}
