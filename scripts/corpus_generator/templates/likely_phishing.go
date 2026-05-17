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
			pool.t("As part of our scheduled IT hygiene, please change your password from the company portal at your convenience.",
				"ในการดูแลระบบ IT ตามกำหนด กรุณาเปลี่ยนรหัสผ่านผ่านพอร์ทัลของบริษัทเมื่อสะดวก",
				"定期的なITメンテナンスの一環として、ご都合のよいタイミングで社内ポータルからパスワードを変更してください。",
				"정기 IT 점검의 일환으로, 편하실 때 사내 포털에서 비밀번호를 변경해 주세요.",
				"作为定期 IT 维护的一部分，请在方便时通过公司门户更改您的密码。",
				"Trong khuôn khổ bảo trì IT định kỳ, vui lòng đổi mật khẩu qua cổng nội bộ khi thuận tiện."),
			pool.t("No action is required if you have already rotated credentials this quarter.",
				"หากคุณเปลี่ยนรหัสผ่านในไตรมาสนี้แล้ว ไม่ต้องดำเนินการใด ๆ",
				"今四半期にすでにパスワードを更新されている場合は、対応は不要です。",
				"이번 분기에 이미 비밀번호를 변경하셨다면 별도 조치가 필요하지 않습니다.",
				"如果您本季度已更新过密码，则无需任何操作。",
				"Nếu bạn đã đổi mật khẩu trong quý này thì không cần thực hiện thêm thao tác nào."),
			pool.t("Need help? Reply to this thread and the helpdesk will reach out.",
				"ต้องการความช่วยเหลือ? ตอบกลับอีเมลนี้แล้วทีมเฮลป์เดสก์จะติดต่อกลับ",
				"サポートが必要ですか?このメールに返信いただければヘルプデスクからご連絡します。",
				"도움이 필요하신가요? 본 메일에 답장하시면 헬프데스크에서 연락드리겠습니다.",
				"需要帮助？请回复此邮件，IT 服务台会与您联系。",
				"Cần hỗ trợ? Trả lời email này và bộ phận hỗ trợ sẽ liên hệ với bạn."),
		})
		return Result{
			Payload: Payload{
				From:        emailAddr("itsupport", opts.Tenant),
				FromDisplay: "IT Helpdesk",
				To:          recipient(opts),
				Subject:     subj,
				BodyText:    body,
				// All other templates' benign variants set this so the
				// validator's model-validation path sees a realistic
				// internal-bulletin auth posture rather than an empty
				// header map.
				Headers: map[string]string{
					"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
				},
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
