package security

import (
	"testing"
	"time"
)

func almostEqual(t1, t2 time.Duration) bool {
	diff := t1 - t2
	if diff < 0 {
		diff *= -1
	}
	return diff < time.Second*5
}

func TestRotateTime(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name        string
		created     time.Time
		expire      time.Time
		gracePeriod float64
		expected    time.Duration
	}{
		{
			name:        "already expired",
			created:     now.Add(-time.Second * 2),
			expire:      now.Add(-time.Second),
			gracePeriod: 0.5,
			expected:    0,
		},
		{
			name:        "grace period .50",
			created:     now,
			expire:      now.Add(time.Hour),
			gracePeriod: 0.5,
			expected:    time.Minute * 30,
		},
		{
			name:        "grace period .25",
			created:     now,
			expire:      now.Add(time.Hour),
			gracePeriod: 0.25,
			expected:    time.Minute * 45,
		},
		{
			name:        "grace period .75",
			created:     now,
			expire:      now.Add(time.Hour),
			gracePeriod: 0.75,
			expected:    time.Minute * 15,
		},
		{
			name:        "grace period 1",
			created:     now,
			expire:      now.Add(time.Hour),
			gracePeriod: 1,
			expected:    0,
		},
		{
			name:        "grace period 0",
			created:     now,
			expire:      now.Add(time.Hour),
			gracePeriod: 0,
			expected:    time.Hour,
		},
		{
			name:        "grace period .25 shifted",
			created:     now.Add(time.Minute * 30),
			expire:      now.Add(time.Minute * 90),
			gracePeriod: 0.25,
			expected:    time.Minute * 75,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SecretManager{ConfigOptions: &CertOptions{SecretRotationGracePeriodRatio: tt.gracePeriod}}
			got := sc.RotateTime(SecretItem{CreatedTime: tt.created, ExpireTime: tt.expire})
			if !almostEqual(got, tt.expected) {
				t.Fatalf("expected %v got %v", tt.expected, got)
			}
		})
	}
}
