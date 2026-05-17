package templates

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// VendorCompromise generates emails sent from a previously-known
// vendor mailbox whose credentials are now under attacker control —
// e.g. mid-thread bank-detail change, payment-portal redirect.
type VendorCompromise struct{}

// NewVendorCompromise returns a fresh generator.
func NewVendorCompromise() *VendorCompromise { return &VendorCompromise{} }

// Category implements Generator.
func (g *VendorCompromise) Category() constant.Category {
	return constant.CategoryVendorCompromise
}

// Generate implements Generator.
func (g *VendorCompromise) Generate(opts Options) Result {
	pool := localePool(opts.Locale)
	vendors := []string{"alpha-supply.com", "beta-logistics.com", "gamma-print.com"}
	vendor := vendors[opts.Index%len(vendors)]

	if !opts.IsThreat {
		return Result{
			Payload: Payload{
				From:        emailAddr("ar", vendor),
				FromDisplay: "Alpha Supply A/R",
				To:          recipient(opts),
				Subject:     pool.t("Statement for September", "งบประจำเดือนกันยายน", "9月の請求明細", "9월 청구 명세서", "9月对账单", "Bảng kê tháng 9"),
				BodyText:    pool.t("Statement attached. No action required if all entries look correct.", "แนบงบมาแล้ว ตรวจสอบรายการตามปกติ", "明細を添付しました。問題なければ対応不要です", "명세서를 첨부했습니다. 이상 없으면 추가 조치 불필요", "随附对账单，如无异常无需处理", "Đính kèm bảng kê, không cần xử lý nếu không có sai sót"),
				Headers:     map[string]string{"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
			},
			AttackType:      "Routine vendor statement",
			Description:     "Established vendor sending routine statement — should classify Trusted.",
			ExpectedSignals: []string{"KNOWN_VENDOR", "AUTH_PASS"},
		}
	}

	body := pool.body([]string{
		pool.t("Further to invoice 9821, please note our banking has changed. Effective immediately, route payments to:",
			"แจ้งเปลี่ยนข้อมูลบัญชีธนาคารสำหรับการชำระเงิน มีผลทันที",
			"請求書9821の支払いについて、銀行口座を変更しました。今後は以下にお願いします",
			"송장 9821 관련, 은행 정보가 변경되었습니다. 즉시 아래로 송금해 주세요",
			"关于9821号发票，我们的银行账户已变更，即日起请汇至以下账户",
			"Liên quan đến hóa đơn 9821, thông tin ngân hàng đã thay đổi, vui lòng chuyển tiền vào tài khoản sau"),
		fmt.Sprintf("Bank: %s\nAccount: %s\nSWIFT: %s",
			pick(opts.Rand, []string{"Wells Fargo", "HSBC", "Standard Chartered"}),
			fmt.Sprintf("%010d", opts.Rand.Int63n(9_999_999_999)),
			pick(opts.Rand, []string{"WFBIUS6S", "HSBCHKHH", "SCBLSG22"})),
		pool.t("Apologies for the short notice.", "ขออภัยที่แจ้งกระชั้นชิด", "急なご連絡で恐縮です", "급한 안내 드려 죄송합니다", "抱歉时间紧迫", "Xin lỗi vì thông báo gấp"),
	})

	return Result{
		Payload: Payload{
			From:        emailAddr("ar", vendor),
			FromDisplay: "Alpha Supply A/R",
			To:          recipient(opts),
			Subject: pool.t("Banking details update — invoice 9821",
				"แจ้งเปลี่ยนข้อมูลธนาคาร — ใบแจ้งหนี้ 9821",
				"銀行情報変更のお知らせ — 9821",
				"은행 정보 변경 안내 — 9821",
				"银行账户变更通知 — 9821",
				"Thay đổi thông tin ngân hàng — 9821"),
			BodyText: body,
			Headers: map[string]string{
				"Reply-To":               emailAddr("ar", lookalikeDomain(opts.Rand, vendor)),
				"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
			},
		},
		AttackType:      "Vendor mid-thread bank-detail change",
		Description:     "Previously-known vendor address pushing a banking change with reply-to redirected to a lookalike domain.",
		ExpectedSignals: []string{"KNOWN_VENDOR", "BANK_DETAIL_CHANGE", "REPLY_TO_LOOKALIKE", "MID_THREAD_DEVIATION"},
	}
}
