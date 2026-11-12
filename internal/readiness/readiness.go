package readiness

import (
	"context"
	"sort"
)

type CheckFunc func(context.Context) error

type Check struct {
	Name     string
	Required bool
	Run      CheckFunc
}

type Result struct {
	Status string `json:"status"`
}

type Report struct {
	Status string            `json:"status"`
	Checks map[string]Result `json:"checks"`
}

type Checker struct {
	checks []Check
}

func New(checks ...Check) *Checker {
	return &Checker{checks: append([]Check(nil), checks...)}
}

func (c *Checker) Check(ctx context.Context) Report {
	report := Report{Status: "ok", Checks: make(map[string]Result, len(c.checks))}
	checks := append([]Check(nil), c.checks...)
	sort.Slice(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })
	for _, check := range checks {
		if check.Name == "" || check.Run == nil {
			continue
		}
		if err := check.Run(ctx); err != nil {
			report.Checks[check.Name] = Result{Status: "failed"}
			if check.Required {
				report.Status = "not_ready"
			}
			continue
		}
		report.Checks[check.Name] = Result{Status: "ok"}
	}
	return report
}
