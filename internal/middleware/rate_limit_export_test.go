package middleware

import "time"

// RateLimiterSweepIdle drives the idle-bucket janitor synchronously
// for tests. Exported via the *_test.go file so production callers
// don't see it.
func RateLimiterSweepIdle(rl *RateLimiter, now time.Time) int {
	return rl.sweepIdle(now)
}
