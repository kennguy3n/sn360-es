package templates

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// InvoiceFraud generates fake-invoice / payment-redirection emails:
// PDF or HTML invoice purporting to be from a vendor, often with a
// lookalike sender domain and a "Pay Now" link pointing to a
// freshly-registered redirector.
type InvoiceFraud struct{}

// NewInvoiceFraud returns a fresh generator.
func NewInvoiceFraud() *InvoiceFraud { return &InvoiceFraud{} }

// Category implements Generator.
func (g *InvoiceFraud) Category() constant.Category {
	return constant.CategoryInvoiceFraud
}

// Generate implements Generator.
func (g *InvoiceFraud) Generate(opts Options) Result {
	pool := localePool(opts.Locale)
	vendors := []string{"alpha-supply.com", "beta-logistics.com", "gamma-print.com"}
	vendor := vendors[opts.Index%len(vendors)]
	amount := 1200 + opts.Rand.Intn(50_000)

	if !opts.IsThreat {
		return Result{
			Payload: Payload{
				From:        emailAddr("billing", vendor),
				FromDisplay: "Alpha Supply Billing",
				To:          recipient(opts),
				Subject:     fmt.Sprintf("Invoice INV-%05d", 10000+opts.Index),
				BodyText: pool.t(fmt.Sprintf("Invoice for $%d attached. Net 30 terms apply. Pay via the same ACH details on file.", amount),
					fmt.Sprintf("ใบแจ้งหนี้ %d บาท แนบมาด้วย ชำระตามข้อมูลธนาคารเดิม", amount),
					fmt.Sprintf("%d 円の請求書を添付しました。既存の口座にお支払いください", amount),
					fmt.Sprintf("청구서 %d원이 첨부되어 있습니다. 기존 계좌로 결제해 주세요", amount),
					fmt.Sprintf("发票金额 %d 元已附上，请按原账户付款", amount),
					fmt.Sprintf("Hóa đơn %d đính kèm, vui lòng thanh toán theo tài khoản đã đăng ký", amount)),
				Headers: map[string]string{"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
				Attachments: []Attachment{{
					Filename:    fmt.Sprintf("INV-%05d.pdf", 10000+opts.Index),
					ContentType: "application/pdf",
					SizeBytes:   85_000,
				}},
			},
			AttackType:      "Legitimate vendor invoice",
			Description:     "Genuine vendor invoice with consistent banking and authenticated sender — should classify Trusted/Informational.",
			ExpectedSignals: []string{"KNOWN_VENDOR", "AUTH_PASS"},
		}
	}

	impostor := lookalikeDomain(opts.Rand, vendor)
	payLink := suspiciousLoginURL(opts.Rand, opts.Difficulty)

	body := pool.body([]string{
		pool.t(fmt.Sprintf("Please find invoice INV-%05d for $%d due immediately. Pay via the secure link below.", 90000+opts.Index, amount),
			fmt.Sprintf("ใบแจ้งหนี้ %d บาท ครบกำหนดทันที ชำระผ่านลิงก์ด้านล่าง", amount),
			fmt.Sprintf("%d 円の請求書、本日中にお支払いください", amount),
			fmt.Sprintf("청구서 %d원 즉시 결제 부탁드립니다", amount),
			fmt.Sprintf("发票金额 %d 元请立即支付", amount),
			fmt.Sprintf("Hóa đơn %d cần thanh toán ngay", amount)),
		fmt.Sprintf("%s: %s", pool.t("Pay Now", "ชำระทันที", "今すぐ支払う", "지금 결제", "立即付款", "Thanh toán ngay"), payLink),
	})

	return Result{
		Payload: Payload{
			From:        emailAddr("billing", impostor),
			FromDisplay: "Alpha Supply Billing",
			To:          recipient(opts),
			Subject:     fmt.Sprintf("URGENT: Past-due invoice INV-%05d", 90000+opts.Index),
			BodyText:    body,
			Headers: map[string]string{
				"Reply-To":               emailAddr("ar", impostor),
				"Authentication-Results": "spf=fail dkim=none dmarc=fail",
			},
		},
		AttackType:      "Fake invoice with lookalike vendor",
		Description:     "Invoice fraud sent from a lookalike of a known vendor, with payment redirected via a fresh-domain link.",
		ExpectedSignals: []string{"LOOKALIKE_SENDER_DOMAIN", "INVOICE_PRETEXT", "PAYMENT_REDIRECT_URL", "AUTH_FAIL"},
	}
}
