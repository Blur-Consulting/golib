package api

type Result struct {
	Result  interface{} `json:"result"`
	Success bool        `json:"success"`
	Error   Error       `json:"error"`
}

type ArrayResult struct {
	Items      interface{} `json:"items"`
	TotalCount int64       `json:"totalCount"`
}

type ArrayResultMore struct {
	Items   interface{} `json:"items"`
	HasMore bool        `json:"hasMore"`
}

type Error struct {
	Code     int    `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	Details  string `json:"details,omitempty"`
	err      error
	status   int
	internal bool // an internal Error must be created by New()
}
