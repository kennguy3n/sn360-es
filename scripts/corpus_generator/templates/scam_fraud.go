package templates

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// ScamFraud generates classic mass-market scams — advance-fee fraud,
// lottery/inheritance windfalls, fake job offers, romance bait.
type ScamFraud struct{}

// NewScamFraud returns a fresh generator.
func NewScamFraud() *ScamFraud { return &ScamFraud{} }

// Category implements Generator.
func (g *ScamFraud) Category() constant.Category {
	return constant.CategoryScamFraud
}

// Generate implements Generator.
func (g *ScamFraud) Generate(opts Options) Result {
	pool := localePool(opts.Locale)

	if !opts.IsThreat {
		return Result{
			Payload: Payload{
				From:        emailAddr("alumni", "university.example"),
				FromDisplay: "University Alumni Office",
				To:          recipient(opts),
				Subject:     pool.t("Alumni newsletter", "จดหมายข่าวศิษย์เก่า", "卒業生ニュースレター", "동문 뉴스레터", "校友通讯", "Bản tin cựu sinh viên"),
				BodyText:    pool.t("Annual fundraising update — no purchase necessary, donations are optional.", "อัปเดตการระดมทุนประจำปี การบริจาคไม่บังคับ", "年次募金の最新情報、寄付は任意です", "연례 모금 안내, 기부는 선택사항입니다", "年度筹款更新，捐款自愿", "Cập nhật gây quỹ thường niên, đóng góp tự nguyện"),
				Headers: map[string]string{
					"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
					"List-Unsubscribe":       "<mailto:unsub@university.example>",
				},
			},
			AttackType:      "Legitimate fundraising newsletter",
			Description:     "Real alumni newsletter offering optional donations — should classify Informational.",
			ExpectedSignals: []string{"AUTH_PASS", "LIST_UNSUBSCRIBE_PRESENT"},
		}
	}

	amount := 1_000_000 + opts.Rand.Intn(9_000_000)
	body := pool.body([]string{
		pool.t(fmt.Sprintf("Congratulations! You have been selected to receive $%d USD as part of an international lottery promotion.", amount),
			fmt.Sprintf("ขอแสดงความยินดี! คุณได้รับรางวัล %d บาทจากการจับฉลากระดับนานาชาติ", amount),
			fmt.Sprintf("おめでとうございます！国際抽選で %d 円が当選しました", amount),
			fmt.Sprintf("축하합니다! 국제 추첨에서 %d 원에 당첨되셨습니다", amount),
			fmt.Sprintf("恭喜！您在国际抽奖中获得 %d 元", amount),
			fmt.Sprintf("Xin chúc mừng! Bạn đã trúng %d trong xổ số quốc tế", amount)),
		pool.t("To claim, send your full name, address, and a $500 processing fee to our agent.",
			"กรุณาส่งชื่อ-นามสกุล ที่อยู่ และค่าธรรมเนียม 500 ดอลลาร์",
			"請求するには氏名、住所、500ドルの手数料を送ってください",
			"청구하시려면 이름, 주소, $500 수수료를 보내주세요",
			"请发送您的姓名、地址和 500 美元手续费以领取奖金",
			"Để nhận thưởng vui lòng gửi họ tên, địa chỉ và phí 500 USD"),
	})

	return Result{
		Payload: Payload{
			From:        randomFreemailSender(opts.Rand, "agent"),
			FromDisplay: "International Lottery Commission",
			To:          recipient(opts),
			Subject:     pool.t("YOU HAVE WON!", "คุณถูกรางวัล!", "ご当選おめでとうございます!", "당첨되셨습니다!", "您中奖了！", "Bạn đã trúng thưởng!"),
			BodyText:    body,
			Headers:     map[string]string{"Authentication-Results": "spf=none dkim=none dmarc=none"},
		},
		AttackType:      "Advance-fee lottery scam",
		Description:     "Classic lottery / advance-fee scam asking for a processing fee to release fictitious winnings.",
		ExpectedSignals: []string{"ADVANCE_FEE_REQUEST", "EXTREME_REWARD", "FREEMAIL_SENDER", "AUTH_FAIL"},
	}
}
