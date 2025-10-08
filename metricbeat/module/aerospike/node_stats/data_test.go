package node_stats

import (
	"reflect"
	"testing"
)

// TestConvertBatchIndexQueueInternal runs tests for successful parsing,
// as well as various error conditions (format, non-numeric, overflow).
func TestConvertBatchIndexQueueInternal(t *testing.T) {
	// Define the structure for a single test case
	type testCase struct {
		name    string
		input   string
		want    []map[string]uint64
		wantErr bool
		errType error // Used to check if the wrapped error is a specific type (e.g., *strconv.NumError)
	}

	// Define the expected output for the successful cases
	wantSuccess := []map[string]uint64{
		{"requests": 15, "buffers": 5},
		{"requests": 0, "buffers": 0},
		{"requests": 22, "buffers": 18},
	}
	wantIdle := make([]map[string]uint64, 9)
	for i := range wantIdle {
		wantIdle[i] = map[string]uint64{"requests": 0, "buffers": 0}
	}

	tests := []testCase{
		{
			name:    "Success_Idle_9_Queues",
			input:   "0:0,0:0,0:0,0:0,0:0,0:0,0:0,0:0,0:0",
			want:    wantIdle,
			wantErr: false,
		},
		{
			name:    "Success_Mixed_Load_3_Queues",
			input:   "15:5,0:0,22:18",
			want:    wantSuccess,
			wantErr: false,
		},
		{
			name:    "Failure_Invalid_Segment_Count",
			input:   "1:1,2", // Missing colon and buffer value for the second segment
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Failure_Non_Numeric_Request",
			input:   "1:1,A:2", // 'A' cannot be parsed as a uint
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Failure_Non_Numeric_Buffer",
			input:   "1:1,2:B", // 'B' cannot be parsed as a uint
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Failure_Value_Too_Large",
			input:   "1:1,18446744073709551616:1", // Value exceeds max uint64 (18446744073709551615)
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Failure_Leading_Comma",
			input:   ",1:1", // A leading comma creates an empty first element
			want:    nil,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := convertBatchIndexQueueInternal(tc.input)

			// 1. Check for expected error state (whether an error occurred)
			if (err != nil) != tc.wantErr {
				t.Fatalf("convertBatchIndexQueueInternal() error = %v, wantErr %v", err, tc.wantErr)
			}

			// 2. Check for correct parsed data on success
			if !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("convertBatchIndexQueueInternal() got = %v, want %v", got, tc.want)
			}

			if tc.wantErr && err != nil {
				t.Logf("convertBatchIndexQueueInternal() expected error occurred: %v", err)
			}
		})
	}
}
