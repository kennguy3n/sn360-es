package templates

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// AccountTakeoverSuspected generates emails sent from a (presumably)
// internal mailbox after a credential compromise. Hallmarks: new
// recipient pattern, inbox-rule abuse, suspicious forwarding setup,
// requests to send sensitive material outside the org.
type AccountTakeoverSuspected struct{}

// NewAccountTakeoverSuspected returns a fresh generator.
func NewAccountTakeoverSuspected() *AccountTakeoverSuspected {
	return &AccountTakeoverSuspected{}
}

// Category implements Generator.
func (g *AccountTakeoverSuspected) Category() constant.Category {
	return constant.CategoryAccountTakeoverSuspected
}

// Generate implements Generator.
func (g *AccountTakeoverSuspected) Generate(opts Options) Result {
	pool := localePool(opts.Locale)

	user := []string{"alice", "bob", "carol", "david"}[opts.Index%4]
	if !opts.IsThreat {
		// Benign: a real internal user asking IT for help — should NOT trip ATO.
		body := pool.body([]string{
			pool.t("I think I clicked on a suspicious link earlier today. Can you check my account for anything unusual?",
				"ฉันคิดว่าฉันคลิกลิงก์น่าสงสัยเมื่อเช้านี้ ช่วยตรวจสอบบัญชีของฉันด้วย",
				"今朝、不審なリンクをクリックしてしまったかもしれません。アカウントを確認していただけますか",
				"오늘 아침에 의심스러운 링크를 클릭한 것 같아요. 계정을 확인해 주실 수 있나요",
				"我今早可能点击了一个可疑链接，能否帮我检查一下账户",
				"Sáng nay tôi có thể đã bấm vào liên kết đáng ngờ, anh/chị giúp kiểm tra tài khoản"),
		})
		return Result{
			Payload: Payload{
				From:        emailAddr(user, opts.Tenant),
				FromDisplay: user + " (User)",
				To:          emailAddr("itsupport", opts.Tenant),
				Subject:     pool.t("Possible phishing click", "อาจคลิกลิงก์ฟิชชิ่ง", "フィッシングをクリックしたかも", "피싱 링크 클릭 의심", "可能误点钓鱼链接", "Có thể đã bấm liên kết lừa đảo"),
				BodyText:    body,
				Headers:     map[string]string{"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
			},
			AttackType:      "User self-report",
			Description:     "Internal user proactively reporting a suspicious click — must not be flagged as ATO.",
			ExpectedSignals: []string{"INTERNAL_ORIGIN", "USER_INITIATED_REPORT"},
		}
	}

	body := pool.body([]string{
		pool.t("Quick favour — I'm in a meeting and need you to forward me the latest payroll export and the W-2 spreadsheet to my personal address.",
			"ช่วยส่งไฟล์เงินเดือนล่าสุดและสเปรดชีต W-2 ไปที่อีเมลส่วนตัวของฉันหน่อย ฉันอยู่ในประชุม",
			"会議中なので、最新の給与データと W-2 を私の個人アドレスに転送してください",
			"회의 중이어서요, 최신 급여 자료와 W-2 시트를 제 개인 이메일로 전달해 주세요",
			"我在开会，请把最新工资数据和 W-2 表格转发到我的私人邮箱",
			"Đang họp, vui lòng chuyển dữ liệu lương mới nhất và bảng W-2 đến email cá nhân của tôi"),
		fmt.Sprintf("Send to: %s", randomFreemailSender(opts.Rand, user)),
	})

	return Result{
		Payload: Payload{
			From:        emailAddr(user, opts.Tenant),
			FromDisplay: user,
			To:          emailAddr("payroll", opts.Tenant),
			Subject: pool.t("URGENT — need payroll export now",
				"ด่วน — ขอไฟล์เงินเดือน",
				"至急 — 給与データ送ってください",
				"긴급 — 급여 데이터 보내주세요",
				"紧急 — 请发送工资数据",
				"GẤP — gửi dữ liệu lương"),
			BodyText: body,
			Headers: map[string]string{
				"Reply-To":               randomFreemailSender(opts.Rand, user),
				"X-Mailer":               "OWA/16.0",
				"Authentication-Results": "spf=pass dkim=pass dmarc=pass",
				"X-Originating-IP":       fmt.Sprintf("[%d.%d.%d.%d]", 80+opts.Rand.Intn(100), opts.Rand.Intn(256), opts.Rand.Intn(256), opts.Rand.Intn(256)),
			},
		},
		AttackType:      "Compromised internal mailbox exfil request",
		Description:     "Email sent from an authenticated internal mailbox requesting payroll exfiltration to a personal address — classic ATO signal.",
		ExpectedSignals: []string{"REPLY_TO_EXTERNAL_FREEMAIL", "SENSITIVE_DATA_REQUEST", "FOREIGN_IP_ORIGIN", "OUT_OF_BAND_URGENCY"},
	}
}
