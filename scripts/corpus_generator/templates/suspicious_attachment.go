package templates

import (
	"fmt"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// SuspiciousAttachment generates emails carrying attachments that
// trigger the attachment-pre-scan heuristics: macro-enabled Office
// docs, .exe disguised as PDFs, password-protected archives, etc.
type SuspiciousAttachment struct{}

// NewSuspiciousAttachment returns a fresh generator.
func NewSuspiciousAttachment() *SuspiciousAttachment { return &SuspiciousAttachment{} }

// Category implements Generator.
func (g *SuspiciousAttachment) Category() constant.Category {
	return constant.CategorySuspiciousAttachment
}

// Generate implements Generator.
func (g *SuspiciousAttachment) Generate(opts Options) Result {
	pool := localePool(opts.Locale)
	if !opts.IsThreat {
		return Result{
			Payload: Payload{
				From:        emailAddr("hr", opts.Tenant),
				FromDisplay: "Acme HR",
				To:          recipient(opts),
				Subject:     pool.t("Updated employee handbook", "คู่มือพนักงานฉบับปรับปรุง", "従業員ハンドブック更新", "직원 핸드북 업데이트", "员工手册更新", "Cập nhật sổ tay nhân viên"),
				BodyText:    pool.t("Please find the latest handbook attached.", "กรุณาตรวจสอบคู่มือฉบับล่าสุดที่แนบมา", "最新版のハンドブックを添付しました", "최신 핸드북을 첨부했습니다", "请查看附件中的最新手册", "Vui lòng xem sổ tay mới đính kèm"),
				Headers:     map[string]string{"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
				Attachments: []Attachment{{
					Filename:    "employee_handbook_v3.pdf",
					ContentType: "application/pdf",
					SizeBytes:   1_245_000,
				}},
			},
			AttackType:      "Legitimate PDF handbook",
			Description:     "Clean PDF attachment from internal HR — should not trip attachment heuristics.",
			ExpectedSignals: []string{"INTERNAL_ORIGIN", "ATTACHMENT_BENIGN"},
		}
	}

	var att Attachment
	signals := []string{"SUSPICIOUS_ATTACHMENT"}
	switch opts.Difficulty {
	case LevelEasy:
		att = Attachment{
			Filename:       "Invoice_8821.pdf.exe",
			ContentType:    "application/x-msdownload",
			SizeBytes:      2_300_000,
			DecoyExtension: true,
		}
		signals = append(signals, "DOUBLE_EXTENSION", "EXECUTABLE_PAYLOAD")
	case LevelMedium:
		att = Attachment{
			Filename:     "PO-2024-Q4.docm",
			ContentType:  "application/vnd.ms-word.document.macroenabled.12",
			SizeBytes:    187_000,
			MacroEnabled: true,
		}
		signals = append(signals, "MACRO_ENABLED_OFFICE")
	default:
		att = Attachment{
			Filename:    "remittance_advice.zip",
			ContentType: "application/zip",
			SizeBytes:   34_000,
		}
		signals = append(signals, "PASSWORD_PROTECTED_ARCHIVE")
	}

	bodyText := strings.Join([]string{
		pool.t("Please open the attached document at your earliest convenience.",
			"กรุณาเปิดเอกสารที่แนบโดยเร็วที่สุด",
			"添付ファイルをお早めにご確認ください",
			"가능한 빨리 첨부 파일을 열어주세요",
			"请尽快打开附件",
			"Vui lòng mở tệp đính kèm sớm nhất có thể"),
		pool.t("Password: invoice2024", "รหัสผ่าน: invoice2024", "パスワード: invoice2024", "비밀번호: invoice2024", "密码: invoice2024", "Mật khẩu: invoice2024"),
	}, "\n\n")

	return Result{
		Payload: Payload{
			From:        randomFreemailSender(opts.Rand, "ap"),
			FromDisplay: "Accounts Payable",
			To:          recipient(opts),
			Subject:     fmt.Sprintf("Invoice %d", 8000+opts.Index),
			BodyText:    bodyText,
			Headers:     map[string]string{"Authentication-Results": "spf=none dkim=none dmarc=none"},
			Attachments: []Attachment{att},
		},
		AttackType:      "Weaponised attachment",
		Description:     "Email carrying an attachment that should fail attachment heuristics (executable, macro-enabled, or password-protected).",
		ExpectedSignals: signals,
	}
}
