package handlers

import (
	"encoding/json"
	"net/http"
)

// CommandRequest represents a validated command request.
type CommandRequest struct {
	AgentID string `json:"agent_id"`
	Command string `json:"command"`
	Timeout uint32 `json:"timeout"`
}

// ValidateCommandRequest parses and validates a command execution request.
func ValidateCommandRequest(w http.ResponseWriter, req *http.Request) (*CommandRequest, bool) {
	if req.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return nil, false
	}

	var cmdReq CommandRequest
	if err := json.NewDecoder(req.Body).Decode(&cmdReq); err != nil {
		http.Error(w, "invalid JSON", 400)
		return nil, false
	}

	if cmdReq.AgentID == "" || cmdReq.Command == "" {
		http.Error(w, "agent_id and command required", 400)
		return nil, false
	}

	return &cmdReq, true
}

// BroadcastRequest represents a validated broadcast request.
type BroadcastRequest struct {
	Command string `json:"command"`
}

// ValidateBroadcastRequest parses and validates a broadcast request.
func ValidateBroadcastRequest(w http.ResponseWriter, req *http.Request) (string, bool) {
	if req.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return "", false
	}

	var bcastReq BroadcastRequest
	if err := json.NewDecoder(req.Body).Decode(&bcastReq); err != nil {
		http.Error(w, "invalid JSON", 400)
		return "", false
	}

	if bcastReq.Command == "" {
		http.Error(w, "command required", 400)
		return "", false
	}

	return bcastReq.Command, true
}
