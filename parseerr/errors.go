package parseerr

import "fmt"

type ParserError struct {
	Code    string
	Message string
}

func (e *ParserError) Error() string { return e.Message }

func NewParserError(code, message string) *ParserError {
	return &ParserError{Code: code, Message: message}
}

var (
	ErrInvalidURL  = &ParserError{Code: "INVALID_URL", Message: "Please enter a valid TikTok video link."}
	ErrNotFound    = &ParserError{Code: "VIDEO_NOT_FOUND", Message: "This video was not found. It may have been deleted."}
	ErrPrivate     = &ParserError{Code: "VIDEO_PRIVATE", Message: "This video is private and can't be downloaded."}
	ErrUnsupported = &ParserError{Code: "UNSUPPORTED_MEDIA", Message: "This link doesn't point to a downloadable video."}
)

func UpstreamError(msg string) *ParserError {
	if msg == "" {
		msg = "TikTok returned an unexpected response. Please try again."
	}
	return &ParserError{Code: "UPSTREAM_ERROR", Message: msg}
}

func InternalError(err error) *ParserError {
	return &ParserError{Code: "INTERNAL_ERROR", Message: fmt.Sprintf("An unexpected error occurred: %v", err)}
}
