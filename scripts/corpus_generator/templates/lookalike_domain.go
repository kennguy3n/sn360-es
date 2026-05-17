package templates

import (
	"fmt"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// LookalikeDomain generates emails whose sender domain is a visual
// look-alike of a well-known brand (homoglyph, character swap,
// punycode, or hyphenated impostor).
type LookalikeDomain struct{}

// NewLookalikeDomain returns a fresh generator.
func NewLookalikeDomain() *LookalikeDomain { return &LookalikeDomain{} }

// Category implements Generator.
func (g *LookalikeDomain) Category() constant.Category {
	return constant.CategoryLookalikeDomain
}

// Generate implements Generator.
func (g *LookalikeDomain) Generate(opts Options) Result {
	pool := localePool(opts.Locale)
	brands := []string{"microsoft.com", "google.com", "apple.com", "paypal.com", "dropbox.com", "amazon.com"}
	brand := brands[opts.Index%len(brands)]
	brandName := strings.TrimSuffix(brand, ".com")

	if !opts.IsThreat {
		// Real brand sending a normal product notification.
		body := pool.body([]string{
			pool.t(fmt.Sprintf("Your %s account preferences were updated.", brandName),
				fmt.Sprintf("การตั้งค่าบัญชี %s ของคุณได้รับการอัปเดต", brandName),
				fmt.Sprintf("%s アカウントの設定が更新されました", brandName),
				fmt.Sprintf("%s 계정 환경설정이 업데이트되었습니다", brandName),
				fmt.Sprintf("您的 %s 帐户偏好已更新", brandName),
				fmt.Sprintf("Tùy chọn tài khoản %s của bạn đã được cập nhật", brandName)),
			pool.t("If this wasn't you, sign in and review your activity.",
				"หากไม่ใช่คุณ กรุณาเข้าสู่ระบบและตรวจสอบกิจกรรมของคุณ",
				"心当たりがない場合は、サインインしてアクティビティを確認してください",
				"본인이 아닌 경우 로그인하여 활동을 확인하세요",
				"如非本人操作，请登录查看活动记录",
				"Nếu không phải bạn, vui lòng đăng nhập và kiểm tra hoạt động"),
		})
		return Result{
			Payload: Payload{
				From:        emailAddr("no-reply", brand),
				FromDisplay: brandName + " Account Team",
				To:          recipient(opts),
				Subject:     pool.t("Account settings updated", "อัปเดตการตั้งค่าบัญชี", "アカウント設定の更新", "계정 설정 업데이트", "帐户设置已更新", "Đã cập nhật cài đặt tài khoản"),
				BodyText:    body,
				Headers: map[string]string{
					"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
				},
			},
			AttackType:      "Genuine brand notification",
			Description:     "Real-brand transactional notification — should not trip lookalike heuristics.",
			ExpectedSignals: []string{"BRAND_DOMAIN_LEGITIMATE", "AUTH_PASS"},
		}
	}

	impostor := lookalikeDomain(opts.Rand, brand)
	subj := pool.t(fmt.Sprintf("[%s] Important security notice", brandName),
		fmt.Sprintf("[%s] ประกาศด้านความปลอดภัย", brandName),
		fmt.Sprintf("[%s] 重要なセキュリティ通知", brandName),
		fmt.Sprintf("[%s] 중요한 보안 알림", brandName),
		fmt.Sprintf("[%s] 重要安全通知", brandName),
		fmt.Sprintf("[%s] Thông báo bảo mật quan trọng", brandName))

	body := pool.body([]string{
		pool.t(fmt.Sprintf("We've detected unusual activity on your %s account. Verify your identity to keep your account secure.", brandName),
			fmt.Sprintf("ตรวจพบกิจกรรมผิดปกติในบัญชี %s ของคุณ กรุณายืนยันตัวตน", brandName),
			fmt.Sprintf("%s アカウントで不審なアクティビティを検出しました。本人確認を行ってください", brandName),
			fmt.Sprintf("%s 계정에서 비정상적인 활동이 감지되었습니다. 본인 인증을 진행해 주세요", brandName),
			fmt.Sprintf("我们检测到您 %s 帐户的异常活动，请验证身份", brandName),
			fmt.Sprintf("Chúng tôi phát hiện hoạt động bất thường trên tài khoản %s của bạn. Vui lòng xác minh danh tính", brandName)),
		fmt.Sprintf("https://%s/secure-verify", impostor),
	})

	return Result{
		Payload: Payload{
			From:        emailAddr("security", impostor),
			FromDisplay: brandName + " Security Team",
			To:          recipient(opts),
			Subject:     subj,
			BodyText:    body,
			Headers: map[string]string{
				"Reply-To":               emailAddr("noreply", impostor),
				"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
			},
		},
		AttackType:      "Lookalike-domain brand impersonation",
		Description:     "Phishing sent from a homoglyph / character-swap of a well-known brand domain.",
		ExpectedSignals: []string{"LOOKALIKE_SENDER_DOMAIN", "BRAND_DISPLAY_NAME_SPOOF"},
	}
}
