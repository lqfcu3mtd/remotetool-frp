package main

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestProbeBatchBudgetAndCancellation(t *testing.T) {
	for _, n := range []int{1, 1024} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			maps := make([]Mapping, n)
			for i := range maps {
				maps[i].ID = fmt.Sprint(i)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			start := time.Now()
			r := collectReports(ctx, maps, nil, nil, func(c context.Context, _ string, _ int) string { <-c.Done(); return "unknown" })
			if time.Since(start) > time.Second {
				t.Fatal("probe batch exceeded bounded cancellation")
			}
			if len(r) != n {
				t.Fatal("missing reports")
			}
			for _, v := range r {
				if v.Target != "unknown" {
					t.Fatal(v)
				}
			}
		})
	}
}
