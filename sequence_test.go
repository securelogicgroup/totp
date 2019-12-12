package totp

import (
	"testing"
	"time"
)

func TestSequence(t *testing.T) {
	now := time.Now()
	expect := []time.Time{now.Add(-time.Minute), now, now.Add(time.Minute)}
	seq := sequence(now.Add(-time.Minute), now.Add(time.Minute), time.Minute)
	for i := range expect {
		if expect[i] != seq[i] {
			t.Errorf("element %d: got %s expected %s", i, seq[i], expect[i])
		}
	}
	expect = []time.Time{now}
	seq = sequence(now, now, time.Duration(0))
	if expect[0] != seq[0] {
		t.Errorf("got %s expected %s", seq[0], expect[0])
	}
}
