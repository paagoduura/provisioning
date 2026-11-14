package migrations

import "testing"

func TestMigrationVersion(t *testing.T) {
	tests := []struct {
		name string
		want int64
		bad  bool
	}{
		{name: "001_init.sql", want: 1},
		{name: "013_provisioning_stage_metadata.sql", want: 13},
		{name: "014_interswitch_webhook_events.sql", want: 14},
		{name: "1_init.sql", bad: true},
		{name: "000_init.sql", bad: true},
		{name: "abc_init.sql", bad: true},
		{name: "014.sql", bad: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := migrationVersion(test.name)
			if test.bad {
				if err == nil {
					t.Fatalf("migrationVersion(%q) unexpectedly succeeded with %d", test.name, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("migrationVersion(%q) = %d, want %d", test.name, got, test.want)
			}
		})
	}
}
