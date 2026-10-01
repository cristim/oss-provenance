package fields

const (
	// correlation_id - string
	// This field is used to correlate
	// the logs emitted by all of our systems.
	// This should be present in all log line
	// emissions.
	CorrelationID = "correlation_id"

	// GitLabUserID - an integer field that
	// captures the user's numeric ID for logging purposes.
	GitLabUserID = "gl_user_id"

	// GitLabUserName - a string field that
	// captures the user's username for logging purposes.
	GitLabUserName = "gl_user_name"

	// ErrorType - a string field that should contain the error type or classification
	// (e.g., "NoMethodError", "ValidationError").
	ErrorType = "error_type"

	// ErrorMessage - a string field that should contain the detailed error message
	// (e.g., "undefined method `boom!' for nil").
	ErrorMessage = "error_message"

	// HTTPStatusCode - an integer field that
	// captures the HTTP status code of requests for logging purposes.
	HTTPStatusCode = "status"

	// HTTPMethod - a string field that captures the HTTP method
	// (e.g., "GET", "POST") of a request for logging purposes.
	HTTPMethod = "method"

	// HTTPURL - a string field that captures the URL of an HTTP request for
	// logging purposes. This should contain only the scheme, host, and path
	// (e.g. "https://example.com/foo"). Query strings and fragments (anchors)
	// must be omitted to avoid logging sensitive information such as tokens
	// or passwords that may appear in query parameters.
	HTTPURL = "url"

	// DurationS - a float64 field that captures the duration of any operation
	// in seconds for logging purposes. It is not limited to HTTP requests and
	// can be used for any timed operation (e.g. database queries, background
	// jobs, external API calls). Using float64 allows sub-second precision to
	// be captured, e.g. 0.032 for a 32ms operation.
	DurationS = "duration_s"

	// RemoteIP - a string field that captures the remote IP
	// address of a request for logging purposes.
	RemoteIP = "remote_ip"

	// TCPAddress - a string field that captures the TCP address a service or
	// component is listening on, in "host:port" format
	// (e.g. "0.0.0.0:8080" or "127.0.0.1:9090").
	TCPAddress = "tcp_address"

	// New fields being added to this section should have
	// the appropriate doc comments added above. These
	// should clearly indicate what the intended use of the
	// field is and should be replicated across the labkit
	// variations.
)
