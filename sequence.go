package totp

import "time"

// sequence generates a sequence of time.Times starting at start, ending at or before
// end, with the given step.
func sequence(start, end time.Time, step time.Duration) []time.Time {
	if start.Sub(end) > 0 {
		tmp := start
		start = end
		end = tmp
	}
	if step == 0 {
		return []time.Time{start}
	}
	var seq []time.Time
	for t := start; t.Sub(end) <= 0; t = t.Add(step) {
		seq = append(seq, t)
	}
	return seq
}
