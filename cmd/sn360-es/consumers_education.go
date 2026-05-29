package main

// This file holds the education-domain consumer handlers split out
// of consumers.go. All subscription orchestration (StartConsumers /
// StopConsumers / trackSub) remains there.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/internal/service/education"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// handleEducationTrigger fans an es.evaluate.result into the
// `es.education.trigger` topic when the verdict tier warrants a
// contextual micro-lesson.
func (a *application) handleEducationTrigger(ctx context.Context, msg events.Message) error {
	if a.eventBus == nil {
		return nil
	}
	var res dto.EvaluateResult
	if err := json.Unmarshal(msg.Data(), &res); err != nil {
		return nil
	}
	if !triggersLesson(res) {
		return nil
	}
	trigger := map[string]string{
		"tenant_id": res.TenantID,
		"category":  string(res.Primary),
		"tier":      string(res.Tier),
	}
	data, err := json.Marshal(trigger)
	if err != nil {
		return nil
	}
	opts := []events.PublishOption{
		events.WithTenantID(res.TenantID),
		events.WithCorrelationID(res.CorrelationID),
	}
	if err := a.eventBus.Publish(ctx, "es.education.trigger", data, opts...); err != nil {
		a.logger.ErrorContext(ctx, "sn360-es: education trigger publish failed; lesson trigger dropped",
			slog.String("tenant_id", res.TenantID),
			slog.String("correlation_id", res.CorrelationID),
			slog.String("tier", string(res.Tier)),
			slog.String("category", string(res.Primary)),
			slog.Any("error", err),
		)
	}
	return nil
}

// simulationSendEnvelope is the wire format expected on
// `es.education.simulation.send`.
type simulationSendEnvelope struct {
	CampaignID string                         `json:"campaign_id"`
	Targets    []simulationSendTargetEnvelope `json:"targets"`
	Params     map[string]string              `json:"params,omitempty"`
}

type simulationSendTargetEnvelope struct {
	UserHash     string `json:"user_hash"`
	MailboxAlias string `json:"mailbox_alias"`
	DisplayName  string `json:"display_name,omitempty"`
}

// handleSimulationSend dispatches a campaign through SimulationEngine.
func (a *application) handleSimulationSend(ctx context.Context, msg events.Message) error {
	if a.simulationEng == nil {
		return nil
	}
	var env simulationSendEnvelope
	if err := json.Unmarshal(msg.Data(), &env); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if env.CampaignID == "" {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send missing campaign_id")
		return nil
	}
	if len(env.Targets) == 0 {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send dropped: empty targets",
			slog.String("campaign_id", env.CampaignID))
		return nil
	}
	targets := make([]education.SimulationTarget, 0, len(env.Targets))
	for _, t := range env.Targets {
		if t.UserHash == "" || t.MailboxAlias == "" {
			continue
		}
		targets = append(targets, education.SimulationTarget{
			UserHash:     t.UserHash,
			MailboxAlias: t.MailboxAlias,
			DisplayName:  t.DisplayName,
		})
	}
	if len(env.Targets) > 0 && len(targets) == 0 {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.send filter dropped all targets",
			slog.String("campaign_id", env.CampaignID),
			slog.Int("raw_targets", len(env.Targets)))
		return nil
	}
	if _, err := a.simulationEng.SendSimulation(ctx, env.CampaignID, targets, env.Params); err != nil {
		return fmt.Errorf("simulation.send: %w", err)
	}
	return nil
}

// handleSimulationResult records an interaction event into the tracker.
func (a *application) handleSimulationResult(ctx context.Context, msg events.Message) error {
	if a.simulationTracker == nil {
		return nil
	}
	var interaction dto.UserInteraction
	if err := json.Unmarshal(msg.Data(), &interaction); err != nil {
		a.logger.WarnContext(ctx, "sn360-es: education.simulation.result unmarshal failed",
			slog.Any("error", err))
		return nil
	}
	if interaction.CampaignID == "" || interaction.UserHash == "" || !interaction.Action.Valid() {
		return nil
	}
	if _, err := a.simulationTracker.RecordInteraction(ctx,
		interaction.CampaignID, interaction.UserHash, interaction.Action); err != nil {
		return fmt.Errorf("simulation.result: %w", err)
	}
	return nil
}

// triggersLesson reports whether the evaluation tier warrants a
// contextual micro-lesson.
func triggersLesson(res dto.EvaluateResult) bool {
	switch res.Tier {
	case constant.TierWarning, constant.TierHighRisk, constant.TierBlocked:
		return true
	}
	return false
}
