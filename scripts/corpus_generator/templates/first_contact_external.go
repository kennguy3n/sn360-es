package templates

import (
	"fmt"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// FirstContactExternal generates emails from senders the tenant has
// never corresponded with. The benign variant is a legitimate cold
// outreach (sales / recruiting); the threat variant pretends to be a
// prior contact to lower the recipient's guard.
type FirstContactExternal struct{}

// NewFirstContactExternal returns a fresh generator.
func NewFirstContactExternal() *FirstContactExternal { return &FirstContactExternal{} }

// Category implements Generator.
func (g *FirstContactExternal) Category() constant.Category {
	return constant.CategoryFirstContactExternal
}

// Generate implements Generator.
func (g *FirstContactExternal) Generate(opts Options) Result {
	pool := localePool(opts.Locale)
	domain := fmt.Sprintf("cold-outreach-%03d.com", opts.Index%500)

	if !opts.IsThreat {
		body := pool.body([]string{
			pool.t(fmt.Sprintf("Hi, I'm reaching out from %s about our analytics platform.", domain),
				fmt.Sprintf("สวัสดี ฉันติดต่อจาก %s เกี่ยวกับแพลตฟอร์มของเรา", domain),
				fmt.Sprintf("%s より、弊社の分析プラットフォームについてご紹介します", domain),
				fmt.Sprintf("%s에서 분석 플랫폼을 소개드리고자 연락드립니다", domain),
				fmt.Sprintf("您好，我来自 %s，向您介绍我们的分析平台", domain),
				fmt.Sprintf("Xin chào, tôi liên hệ từ %s về nền tảng phân tích của chúng tôi", domain)),
			pool.t("If you'd prefer not to hear from us, please reply 'unsubscribe' and I'll remove you from our list.",
				"หากไม่สนใจ กรุณาตอบกลับ 'unsubscribe' เราจะลบรายชื่อของคุณ",
				"ご不要であれば 'unsubscribe' とご返信ください",
				"원치 않으시면 'unsubscribe'로 회신해 주세요",
				"如不感兴趣，请回复 'unsubscribe'",
				"Nếu không quan tâm, vui lòng trả lời 'unsubscribe'"),
		})
		return Result{
			Payload: Payload{
				From:        emailAddr("sales", domain),
				FromDisplay: "Cold Outreach Sales",
				To:          recipient(opts),
				Subject:     pool.t("Quick intro", "แนะนำสั้น ๆ", "簡単なご挨拶", "간단한 소개", "简单介绍", "Giới thiệu nhanh"),
				BodyText:    body,
				Headers: map[string]string{
					"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
					"List-Unsubscribe":       fmt.Sprintf("<mailto:unsub@%s>", domain),
				},
			},
			AttackType:      "Legitimate cold outreach",
			Description:     "First-contact-external sales email that authenticates and offers unsubscribe — should label Informational, not flag.",
			ExpectedSignals: []string{"FIRST_CONTACT_EXTERNAL", "AUTH_PASS", "LIST_UNSUBSCRIBE_PRESENT"},
		}
	}

	body := pool.body([]string{
		pool.t(fmt.Sprintf("Following up on our last conversation — please send the updated bank details to %s.", emailAddr("ar", domain)),
			fmt.Sprintf("ต่อจากการสนทนาครั้งก่อน กรุณาส่งรายละเอียดบัญชีธนาคารใหม่ไปยัง %s", emailAddr("ar", domain)),
			fmt.Sprintf("先日の打ち合わせの件で、更新後の銀行情報を %s 宛にお送りください", emailAddr("ar", domain)),
			fmt.Sprintf("지난 대화에 이어 변경된 은행 정보를 %s 로 보내주세요", emailAddr("ar", domain)),
			fmt.Sprintf("继上次沟通后，请将更新后的银行信息发送至 %s", emailAddr("ar", domain)),
			fmt.Sprintf("Tiếp nối cuộc trò chuyện trước, vui lòng gửi thông tin ngân hàng mới đến %s", emailAddr("ar", domain))),
	})

	return Result{
		Payload: Payload{
			From:        emailAddr("john.smith", domain),
			FromDisplay: "John Smith",
			To:          recipient(opts),
			Subject:     pool.t("Re: invoice follow-up", "Re: ติดตามใบแจ้งหนี้", "Re: 請求書のフォロー", "Re: 송장 후속 조치", "Re: 发票跟进", "Re: theo dõi hóa đơn"),
			BodyText:    body,
			Headers:     map[string]string{"Authentication-Results": "spf=none dkim=none dmarc=none"},
		},
		AttackType:      "First-contact pretending to be prior thread",
		Description:     "Brand-new external sender claiming a previous conversation, asking to update banking details.",
		ExpectedSignals: []string{"FIRST_CONTACT_EXTERNAL", "FAKE_REPLY_PREFIX", "BANK_DETAIL_CHANGE", "AUTH_FAIL"},
	}
}

// unused but keeps strings import in case future templates want it.
var _ = strings.Builder{}
