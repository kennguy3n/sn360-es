package templates

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// VendorTrusted generates emails from established / allow-listed
// vendors. Benign variants should be Tier 0 bypassed; threat
// variants represent the rare case where a long-known vendor
// suddenly behaves anomalously enough to warrant scrutiny.
type VendorTrusted struct{}

// NewVendorTrusted returns a fresh generator.
func NewVendorTrusted() *VendorTrusted { return &VendorTrusted{} }

// Category implements Generator.
func (g *VendorTrusted) Category() constant.Category {
	return constant.CategoryVendorTrusted
}

// Generate implements Generator.
func (g *VendorTrusted) Generate(opts Options) Result {
	pool := localePool(opts.Locale)
	vendors := []string{"alpha-supply.com", "beta-logistics.com", "gamma-print.com", "delta-software.com"}
	vendor := vendors[opts.Index%len(vendors)]

	if !opts.IsThreat {
		return Result{
			Payload: Payload{
				From:        emailAddr("billing", vendor),
				FromDisplay: vendor + " Billing",
				To:          recipient(opts),
				Subject:     pool.t("Monthly subscription receipt", "ใบเสร็จรายเดือน", "月次サブスク領収書", "월간 구독 영수증", "月度订阅收据", "Biên lai đăng ký hàng tháng"),
				BodyText:    pool.t("Your subscription has renewed. No action required.", "การสมัครของคุณต่ออายุแล้ว ไม่ต้องดำเนินการ", "サブスクリプションが更新されました、対応不要です", "구독이 갱신되었습니다, 별도 조치 불필요", "您的订阅已续订，无需操作", "Đăng ký đã được gia hạn, không cần xử lý"),
				Headers: map[string]string{
					"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
					"List-Unsubscribe":       fmt.Sprintf("<mailto:unsub@%s>", vendor),
				},
			},
			AttackType:      "Routine vendor billing receipt",
			Description:     "Allow-listed vendor's automated billing notification — must Tier 0 bypass and classify Trusted.",
			ExpectedSignals: []string{"KNOWN_VENDOR", "AUTH_PASS", "LIST_UNSUBSCRIBE_PRESENT"},
		}
	}

	return Result{
		Payload: Payload{
			From:        emailAddr("billing", vendor),
			FromDisplay: vendor + " Billing",
			To:          recipient(opts),
			Subject: pool.t("Urgent: contract auto-renewal at 5x rate",
				"ด่วน: ต่ออายุสัญญาเพิ่ม 5 เท่า",
				"至急: 契約自動更新で5倍の金額",
				"긴급: 계약 자동 갱신, 요금 5배",
				"紧急：合同自动续约金额上调5倍",
				"GẤP: gia hạn hợp đồng tự động với mức gấp 5"),
			BodyText: pool.body([]string{
				pool.t("Per the auto-renewal clause, your contract renews tomorrow at a 5x rate. Pay now to avoid the price change.",
					"ตามเงื่อนไขต่ออายุอัตโนมัติ สัญญาจะต่อพรุ่งนี้ในอัตรา 5 เท่า กรุณาชำระทันที",
					"自動更新条項により、契約は明日5倍料金で更新されます。今すぐお支払いください",
					"자동 갱신 조항에 따라 계약이 내일 5배 요금으로 갱신됩니다. 지금 결제하세요",
					"根据自动续约条款，合同明日按5倍价格续签，请立即付款",
					"Theo điều khoản gia hạn, hợp đồng sẽ gia hạn ngày mai với mức gấp 5 lần"),
				fmt.Sprintf("Pay: %s", suspiciousLoginURL(opts.Rand, opts.Difficulty)),
			}),
			Headers: map[string]string{
				"Reply-To":               emailAddr("billing", lookalikeDomain(opts.Rand, vendor)),
				"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
			},
		},
		AttackType:      "Vendor account abused for predatory billing",
		Description:     "Otherwise-trusted vendor sending an abusive auto-renewal demand with payment redirected to a lookalike domain.",
		ExpectedSignals: []string{"KNOWN_VENDOR", "REPLY_TO_LOOKALIKE", "URGENT_TONE", "PAYMENT_REDIRECT_URL"},
	}
}
