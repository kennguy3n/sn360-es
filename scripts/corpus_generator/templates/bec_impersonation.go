package templates

import (
	"fmt"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// BECImpersonation generates Business Email Compromise emails where
// the attacker spoofs an executive's display name (often with a
// reply-to mismatch) and requests a wire transfer or gift card.
type BECImpersonation struct{}

// NewBECImpersonation returns a fresh generator.
func NewBECImpersonation() *BECImpersonation { return &BECImpersonation{} }

// Category implements Generator.
func (g *BECImpersonation) Category() constant.Category {
	return constant.CategoryBECImpersonation
}

// Generate implements Generator.
func (g *BECImpersonation) Generate(opts Options) Result {
	pool := localePool(opts.Locale)
	ceos := []struct{ Name, Title string }{
		{"David Chen", "CEO"}, {"Akira Tanaka", "CEO"}, {"Maria Sousa", "CFO"},
		{"Liam O'Connor", "Managing Director"}, {"Priya Sharma", "Finance Director"},
		{"Nguyen Thi Lan", "CEO"}, {"Somchai Suk", "Operations Director"},
	}
	exec := ceos[opts.Index%len(ceos)]

	if !opts.IsThreat {
		body := pool.body([]string{
			pool.t(fmt.Sprintf("Hi, just a heads-up that I'll be travelling next week. %s will be covering payment approvals.", strings.Split(exec.Name, " ")[0]),
				"สวัสดี ฉันจะเดินทางสัปดาห์หน้า กรุณาประสานงานเรื่องการอนุมัติชำระเงินตามปกติ",
				"来週は出張ですので、通常通り支払い承認をお願いします",
				"다음 주에 출장 갑니다. 평소대로 결제 승인을 진행해 주세요",
				"我下周出差，请按惯例处理付款审批",
				"Tuần tới tôi đi công tác, vui lòng xử lý phê duyệt thanh toán như thường lệ"),
			"Thanks,\n" + exec.Name,
		})
		return Result{
			Payload: Payload{
				From:        emailAddr(strings.ToLower(strings.ReplaceAll(strings.Split(exec.Name, " ")[0], "'", "")), opts.Tenant),
				FromDisplay: exec.Name,
				To:          recipient(opts),
				Subject:     pool.t("OOO next week", "ลาพักร้อนสัปดาห์หน้า", "来週不在", "다음 주 부재", "下周不在", "Vắng mặt tuần tới"),
				BodyText:    body,
				Headers: map[string]string{
					"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
				},
			},
			AttackType:      "Benign executive OOO note",
			Description:     "Legitimate internal OOO note from a known executive — should NOT be flagged as BEC.",
			ExpectedSignals: []string{"INTERNAL_ORIGIN", "AUTH_PASS"},
		}
	}

	amount := 18000 + opts.Rand.Intn(82000)
	currency := pool.t("USD", "บาท", "円", "원", "元", "VND")
	urgency := pool.t("URGENT — confidential wire request",
		"ด่วน — คำขอโอนเงินลับ",
		"至急 — 機密送金依頼",
		"긴급 — 기밀 송금 요청",
		"紧急 — 机密汇款请求",
		"GẤP — yêu cầu chuyển tiền mật")

	bodyLines := []string{
		pool.t(fmt.Sprintf("Hi, are you at your desk? I need you to handle a confidential wire transfer of %s %d today. The vendor is expecting payment before close of business.", currency, amount),
			fmt.Sprintf("กรุณาดำเนินการโอนเงินจำนวน %d %s ก่อนสิ้นวันทำการ เป็นความลับ ห้ามแจ้งใคร", amount, currency),
			fmt.Sprintf("本日中に%d %sの送金を機密で処理してください。他の人には伝えないでください", amount, currency),
			fmt.Sprintf("오늘 안에 %d %s 송금을 기밀로 처리해 주세요. 다른 사람에게 말하지 마세요", amount, currency),
			fmt.Sprintf("请在今日下班前秘密办理 %d %s 的电汇，请勿告知他人", amount, currency),
			fmt.Sprintf("Vui lòng xử lý lệnh chuyển khoản mật %d %s trong hôm nay, không thông báo cho ai khác", amount, currency)),
		pool.t("Send me the confirmation directly. Do not loop in finance.",
			"แจ้งยืนยันกับฉันโดยตรง อย่าส่งให้ทีมการเงิน",
			"確認は直接私に送ってください。経理には連絡しないでください",
			"확인은 저에게 직접 보내주세요. 재무팀에는 알리지 마세요",
			"请直接将确认发给我，不要抄送财务",
			"Gửi xác nhận trực tiếp cho tôi, không cần liên hệ phòng tài chính"),
		pool.t("Sent from my iPhone", "ส่งจากโทรศัพท์", "iPhoneより送信", "iPhone에서 보냄", "由iPhone发送", "Gửi từ iPhone"),
	}
	body := strings.Join(bodyLines, "\n\n")

	// Reply-to mismatch is the canonical BEC signal.
	replyTo := randomFreemailSender(opts.Rand, strings.ToLower(strings.Split(exec.Name, " ")[0]))
	from := replyTo
	if opts.Difficulty == LevelHard {
		// On hard difficulty, hide the mismatch by using a lookalike
		// of the tenant domain in the From address.
		from = emailAddr(strings.ToLower(strings.Split(exec.Name, " ")[0]),
			lookalikeDomain(opts.Rand, opts.Tenant))
	}

	signals := []string{"DISPLAY_NAME_SPOOF", "REPLY_TO_MISMATCH", "URGENT_TONE", "WIRE_REQUEST"}
	if opts.Difficulty == LevelHard {
		signals = append(signals, "LOOKALIKE_SENDER_DOMAIN")
	}

	return Result{
		Payload: Payload{
			From:        from,
			FromDisplay: exec.Name + ", " + exec.Title,
			To:          recipient(opts),
			Subject:     urgency,
			BodyText:    body,
			Headers: map[string]string{
				"Reply-To":               replyTo,
				"Authentication-Results": "spf=fail dkim=none dmarc=fail",
			},
		},
		AttackType:      "BEC wire-transfer impersonation",
		Description:     "Display-name spoof of a senior executive requesting a confidential wire transfer with a reply-to mismatch.",
		ExpectedSignals: signals,
	}
}
