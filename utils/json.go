package utils

import (
	"encoding/json"
)

func JsonEncode(data interface{}) string {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(jsonData)
}

func NormalizePayload(input interface{}) interface{} {
	if input == nil {
		return map[string]interface{}{}
	}

	raw, err := json.Marshal(input)
	if err != nil {
		return input
	}

	var normalized interface{}
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return input
	}

	return normalized
}
