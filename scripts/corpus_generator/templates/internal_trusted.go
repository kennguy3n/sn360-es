package templates

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// InternalTrusted generates intra-tenant emails — same primary
// domain on the From and To side. The benign variant should bypass
// Tier 0 entirely; the threat variant is a (rare) compromised
// internal mailbox that nonetheless looks fully internal.
type InternalTrusted struct{}

// NewInternalTrusted returns a fresh generator.
func NewInternalTrusted() *InternalTrusted { return &InternalTrusted{} }

// Category implements Generator.
func (g *InternalTrusted) Category() constant.Category {
	return constant.CategoryInternalTrusted
}

// Generate implements Generator.
func (g *InternalTrusted) Generate(opts Options) Result {
	pool := localePool(opts.Locale)
	people := []string{"alice", "bob", "carol", "david", "emma", "frank"}
	sender := people[opts.Index%len(people)]

	if !opts.IsThreat {
		topics := []string{
			"Meeting recap", "Project plan", "Quarterly OKRs", "Engineering update", "Hiring loop",
		}
		topic := topics[opts.Index%len(topics)]
		return Result{
			Payload: Payload{
				From:        emailAddr(sender, opts.Tenant),
				FromDisplay: sender + "@acme",
				To:          recipient(opts),
				Subject:     pool.t(topic, topic, topic, topic, topic, topic),
				BodyText: pool.t(
					"Sharing notes from today's sync. Let me know if anything is missing.",
					"แนบบันทึกการประชุม หากต้องเพิ่มเติมแจ้งได้",
					"本日の打ち合わせメモを共有します。漏れがあれば教えてください",
					"오늘 회의 메모를 공유합니다. 누락된 부분 알려주세요",
					"分享今天会议的笔记，如有遗漏请告知",
					"Chia sẻ ghi chú họp hôm nay, có gì thiếu hãy báo lại"),
				Headers: map[string]string{
					"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
					"X-Tenant-Origin":        opts.Tenant,
				},
			},
			AttackType:      "Routine internal collaboration",
			Description:     "Intra-tenant message between known internal users — must bypass Tier 0 and classify Trusted.",
			ExpectedSignals: []string{"INTERNAL_ORIGIN", "AUTH_PASS"},
		}
	}

	// Rare threat: account takeover from within the tenant.
	return Result{
		Payload: Payload{
			From:        emailAddr(sender, opts.Tenant),
			FromDisplay: sender,
			To:          emailAddr("finance", opts.Tenant),
			Subject:     pool.t("Quick wire", "ขอโอนเงินด่วน", "至急の送金依頼", "긴급 송금 요청", "紧急汇款", "Chuyển khoản gấp"),
			BodyText: pool.body([]string{
				pool.t(fmt.Sprintf("Are you at your desk? I need to push a same-day wire of $%d to a new supplier.", 30_000+opts.Rand.Intn(50_000)),
					"นั่งโต๊ะอยู่ไหม ต้องโอนวันเดียวกันให้ซัพพลายเออร์ใหม่",
					"今日中に新規取引先に送金が必要です",
					"오늘 신규 거래처로 즉시 송금이 필요해요",
					"在工位吗？今天要给新供应商汇款",
					"Bạn ở bàn không? Cần chuyển khoản trong ngày cho nhà cung cấp mới"),
				pool.t("Send the confirmation to my personal mail — IT has my work account locked.",
					"ส่งคอนเฟิร์มไปอีเมลส่วนตัวฉัน ทีม IT ล็อกแอคเคาท์ไว้",
					"確認は個人メールに送ってください、社用アカウントがロックされています",
					"확인은 개인 메일로 보내주세요. 회사 계정이 잠겨 있어요",
					"请把确认发到我的私人邮箱，公司账号被锁了",
					"Gửi xác nhận đến email cá nhân, tài khoản công ty đang khóa"),
			}),
			Headers: map[string]string{
				"Reply-To":               randomFreemailSender(opts.Rand, sender),
				"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
			},
		},
		AttackType:      "Compromised internal mailbox wire request",
		Description:     "Internal-looking mailbox sending an out-of-band wire request with a personal-email reply-to.",
		ExpectedSignals: []string{"INTERNAL_ORIGIN", "OUT_OF_BAND_URGENCY", "REPLY_TO_EXTERNAL_FREEMAIL", "WIRE_REQUEST"},
	}
}
