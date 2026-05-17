package main

import (
	"math/rand"

	"github.com/kennguy3n/sn360-es/scripts/corpus_generator/templates"
)

// localePools is the per-locale pool of plug-in phrases used by the
// noise injector. Templates have their own per-call translation table
// via templates.Pool.t, but the noise layer needs broader vocabularies
// for greetings, signatures, sign-offs, and currencies that vary
// independently of the email semantics.
//
// All values are PII-free and culturally generic.
type localePools struct {
	Greetings  []string
	SignOffs   []string
	Signatures []string
	Currencies []string
	Names      []string
}

// poolFor returns the locale pool. Unknown locales fall back to en.
func poolFor(loc templates.Locale) localePools {
	switch loc {
	case templates.LocaleTH:
		return localePools{
			Greetings:  []string{"สวัสดีครับ", "เรียนคุณ", "เรียนทีม", "สวัสดีค่ะ"},
			SignOffs:   []string{"ขอแสดงความนับถือ", "ขอบคุณครับ", "ด้วยความเคารพ"},
			Signatures: []string{"ฝ่ายบัญชี", "ทีมไอที", "ฝ่ายจัดซื้อ"},
			Currencies: []string{"บาท", "THB"},
			Names:      []string{"คุณสมชาย", "คุณวิภา", "คุณนิรันดร์"},
		}
	case templates.LocaleJA:
		return localePools{
			Greetings:  []string{"お世話になっております", "いつもお世話になっております", "こんにちは"},
			SignOffs:   []string{"よろしくお願いいたします", "敬具", "ご確認のほどお願いいたします"},
			Signatures: []string{"経理部", "情報システム部", "購買部"},
			Currencies: []string{"円", "JPY"},
			Names:      []string{"田中様", "鈴木様", "佐藤様"},
		}
	case templates.LocaleKO:
		return localePools{
			Greetings:  []string{"안녕하세요", "안녕하십니까", "팀 여러분께"},
			SignOffs:   []string{"감사합니다", "잘 부탁드립니다", "안부 전합니다"},
			Signatures: []string{"재무팀", "IT팀", "구매팀"},
			Currencies: []string{"원", "KRW"},
			Names:      []string{"김민수님", "이지영님", "박철수님"},
		}
	case templates.LocaleZH:
		return localePools{
			Greetings:  []string{"您好", "您好，", "团队您好"},
			SignOffs:   []string{"此致敬礼", "祝好", "顺颂商祺"},
			Signatures: []string{"财务部", "信息技术部", "采购部"},
			Currencies: []string{"元", "CNY", "￥"},
			Names:      []string{"王先生", "李女士", "张经理"},
		}
	case templates.LocaleVI:
		return localePools{
			Greetings:  []string{"Xin chào", "Kính gửi anh/chị", "Chào nhóm"},
			SignOffs:   []string{"Trân trọng", "Cảm ơn", "Kính chúc"},
			Signatures: []string{"Phòng Tài chính", "Phòng IT", "Phòng Mua hàng"},
			Currencies: []string{"đồng", "VND", "₫"},
			Names:      []string{"Anh Nam", "Chị Linh", "Anh Hùng"},
		}
	default:
		return localePools{
			Greetings:  []string{"Hi", "Hello", "Dear team", "Good morning"},
			SignOffs:   []string{"Best regards", "Thanks", "Regards", "Cheers"},
			Signatures: []string{"Accounts Payable", "IT Helpdesk", "Procurement"},
			Currencies: []string{"USD", "$", "EUR", "GBP"},
			Names:      []string{"John", "Sarah", "Mike", "Priya"},
		}
	}
}

// pickFromPool draws one phrase from a slice. Caller's responsibility
// to ensure the slice is non-empty (pools always are).
func pickFromPool(r *rand.Rand, items []string) string {
	return items[r.Intn(len(items))]
}
