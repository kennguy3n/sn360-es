package templates

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// QRPhishing generates emails whose primary lure is a QR code (often
// as a PNG attachment) pointing to a credential-harvest URL. The
// benign variant is a legitimate event-registration mailer where the
// QR resolves to a tenant domain.
type QRPhishing struct{}

// NewQRPhishing returns a fresh generator.
func NewQRPhishing() *QRPhishing { return &QRPhishing{} }

// Category implements Generator.
func (g *QRPhishing) Category() constant.Category {
	return constant.CategoryQRPhishing
}

// Generate implements Generator.
func (g *QRPhishing) Generate(opts Options) Result {
	pool := localePool(opts.Locale)

	if !opts.IsThreat {
		return Result{
			Payload: Payload{
				From:        emailAddr("events", opts.Tenant),
				FromDisplay: "Acme Events",
				To:          recipient(opts),
				Subject:     pool.t("Your conference badge", "บัตรเข้างานของคุณ", "あなたの参加証", "행사 출입증", "您的参会证", "Thẻ tham dự"),
				BodyText:    pool.t("Scan the attached QR to check in.", "สแกน QR ที่แนบเพื่อเช็คอิน", "添付のQRをスキャンして受付してください", "첨부된 QR을 스캔해 체크인하세요", "请扫描附件中的 QR 进行签到", "Quét QR đính kèm để check-in"),
				Headers:     map[string]string{"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
				Attachments: []Attachment{{
					Filename:    "badge_qr.png",
					ContentType: "image/png",
					SizeBytes:   12_000,
					QRTargetURL: fmt.Sprintf("https://events.%s/checkin/%d", opts.Tenant, 1000+opts.Index),
				}},
			},
			AttackType:      "Legitimate event QR badge",
			Description:     "QR attachment resolving to a tenant-owned event URL — should classify Trusted.",
			ExpectedSignals: []string{"QR_PRESENT", "QR_RESOLVES_INTERNAL"},
		}
	}

	target := suspiciousLoginURL(opts.Rand, opts.Difficulty)
	return Result{
		Payload: Payload{
			From:        randomFreemailSender(opts.Rand, "delivery"),
			FromDisplay: "Package Delivery",
			To:          recipient(opts),
			Subject: pool.t("Action required: re-deliver package",
				"ต้องดำเนินการ: นัดส่งพัสดุใหม่",
				"対応必須: 再配達のお願い",
				"필수 조치: 재배송 요청",
				"需要操作：包裹改派",
				"Yêu cầu: giao lại bưu kiện"),
			BodyText: pool.t("Scan the QR below to confirm your delivery address.",
				"สแกน QR ด้านล่างเพื่อยืนยันที่อยู่จัดส่ง",
				"以下のQRをスキャンして配達先を確認してください",
				"아래 QR을 스캔해 배송 주소를 확인하세요",
				"扫描下方 QR 确认收货地址",
				"Quét QR bên dưới để xác nhận địa chỉ giao hàng"),
			Headers: map[string]string{"Authentication-Results": "spf=none dkim=none dmarc=none"},
			Attachments: []Attachment{{
				Filename:    "redelivery.png",
				ContentType: "image/png",
				SizeBytes:   18_000,
				QRTargetURL: target,
			}},
		},
		AttackType:      "QR-coded credential harvest",
		Description:     "QR attachment whose decoded URL points to an off-brand login page — quishing.",
		ExpectedSignals: []string{"QR_PRESENT", "QR_RESOLVES_EXTERNAL", "CREDENTIAL_LINK", "AUTH_FAIL"},
	}
}
