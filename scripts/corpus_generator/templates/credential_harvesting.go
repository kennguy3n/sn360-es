package templates

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// CredentialHarvesting generates emails whose primary goal is to
// extract credentials directly — fake password-expiry notices, MFA
// re-enrolment, document-share-portal logins.
type CredentialHarvesting struct{}

// NewCredentialHarvesting returns a fresh generator.
func NewCredentialHarvesting() *CredentialHarvesting { return &CredentialHarvesting{} }

// Category implements Generator.
func (g *CredentialHarvesting) Category() constant.Category {
	return constant.CategoryCredentialHarvesting
}

// Generate implements Generator.
func (g *CredentialHarvesting) Generate(opts Options) Result {
	pool := localePool(opts.Locale)

	if !opts.IsThreat {
		return Result{
			Payload: Payload{
				From:        emailAddr("security", opts.Tenant),
				FromDisplay: "Acme Security",
				To:          recipient(opts),
				Subject: pool.t("MFA enrolment is mandatory by Friday",
					"การลงทะเบียน MFA ต้องเสร็จภายในวันศุกร์",
					"金曜までに MFA 登録を完了してください",
					"금요일까지 MFA 등록 필수",
					"周五前必须完成 MFA 注册",
					"Bắt buộc đăng ký MFA trước thứ Sáu"),
				BodyText: pool.t("Visit the company SSO portal to enrol your MFA device. No credentials are required from this email.",
					"กรุณาเข้าพอร์ทัล SSO ของบริษัทเพื่อลงทะเบียน MFA อีเมลนี้ไม่ขอข้อมูลใด ๆ",
					"会社の SSO ポータルから MFA を登録してください。本メールでは認証情報を求めません",
					"회사 SSO 포털에서 MFA를 등록하세요. 이 메일은 자격 증명을 요구하지 않습니다",
					"请通过公司 SSO 门户注册 MFA，此邮件不索取任何凭证",
					"Vui lòng đăng ký MFA qua cổng SSO của công ty, email này không yêu cầu thông tin đăng nhập"),
				Headers: map[string]string{"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
			},
			AttackType:      "Legitimate MFA enrolment reminder",
			Description:     "Genuine internal security bulletin requesting users self-enrol via the SSO portal — no credential prompt.",
			ExpectedSignals: []string{"INTERNAL_ORIGIN", "POINTS_TO_SSO_PORTAL"},
		}
	}

	link := suspiciousLoginURL(opts.Rand, opts.Difficulty)
	body := pool.body([]string{
		pool.t("Your mailbox password will expire in 24 hours. Re-confirm your password to keep service active.",
			"รหัสผ่านเมลของคุณจะหมดอายุใน 24 ชั่วโมง กรุณายืนยันรหัสผ่านของคุณ",
			"24時間以内にメールパスワードが失効します。パスワードを再確認してください",
			"24시간 안에 메일 비밀번호가 만료됩니다. 비밀번호를 재확인하세요",
			"您的邮箱密码将在24小时内过期，请重新确认密码",
			"Mật khẩu hộp thư của bạn sẽ hết hạn sau 24 giờ, vui lòng xác nhận lại"),
		fmt.Sprintf("Re-confirm: %s", link),
	})

	return Result{
		Payload: Payload{
			From:        randomFreemailSender(opts.Rand, "passwordreset"),
			FromDisplay: "IT Support",
			To:          recipient(opts),
			Subject: pool.t("Action required: password expiry",
				"ต้องดำเนินการ: รหัสผ่านใกล้หมดอายุ",
				"対応必須: パスワード失効",
				"필수 조치: 비밀번호 만료",
				"需要操作：密码即将过期",
				"Yêu cầu xử lý: mật khẩu sắp hết hạn"),
			BodyText: body,
			BodyHTML: fmt.Sprintf(
				`<p>%s</p><p><a href="%s">%s</a></p>`,
				pool.t("Re-confirm your password.", "ยืนยันรหัสผ่าน", "パスワードを再確認", "비밀번호 재확인", "重新确认密码", "Xác nhận lại mật khẩu"),
				link, pool.t("Verify now", "ยืนยันทันที", "今すぐ確認", "지금 확인", "立即验证", "Xác minh ngay"),
			),
			Headers: map[string]string{"Authentication-Results": "spf=none dkim=none dmarc=none"},
		},
		AttackType:      "Password-expiry credential harvest",
		Description:     "Fake password-expiry warning directing the recipient to an off-brand login page that captures credentials.",
		ExpectedSignals: []string{"CREDENTIAL_PROMPT", "EXTERNAL_LOGIN_DOMAIN", "URGENT_TONE", "PASSWORD_EXPIRY_PRETEXT"},
	}
}
