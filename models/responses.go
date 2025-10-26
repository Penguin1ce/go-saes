package models

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type MeetInTheMiddleKey struct {
	K1Hex       string `json:"k1_hex"`
	K1Bin       string `json:"k1_bin"`
	K2Hex       string `json:"k2_hex"`
	K2Bin       string `json:"k2_bin"`
	CombinedHex string `json:"combined_hex"`
	CombinedBin string `json:"combined_bin"`
}

type MeetInTheMiddleResponse struct {
	Count int                  `json:"count"`
	Keys  []MeetInTheMiddleKey `json:"keys"`
}
