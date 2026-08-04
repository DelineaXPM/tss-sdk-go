package server

import (
	"bytes"
	"strings"
	"testing"
)

const (
	testMessage           = "test %s"
	testExpectedNonNil    = "Expected non-nil logger"
	testExpectedDefault   = "Expected defaultLoggerInstance"
	testExpectedDiscard   = "Expected default logger to be DiscardLogger (silent by default)"
	testExpectedCustom    = "Expected customLogger"
	expectedDiscardLogger = "Expected discardLogger"
)

// mockLogger is a test logger that captures log output
type mockLogger struct {
	buf bytes.Buffer
}

func (m *mockLogger) Printf(format string, v ...interface{}) {
	m.buf.WriteString("Printf: ")
	m.buf.WriteString(format)
	m.buf.WriteString("\n")
}

func (m *mockLogger) Print(v ...interface{}) {
	m.buf.WriteString("Print\n")
}

func (m *mockLogger) Println(v ...interface{}) {
	m.buf.WriteString("Println\n")
}

// TestLoggerInterface verifies that the Logger interface is properly implemented
func TestLoggerInterface(t *testing.T) {
	t.Run("DiscardLogger", func(t *testing.T) {
		var logger Logger = &DiscardLogger{}
		// Should not panic
		logger.Printf(testMessage, "message")
		logger.Print("test")
		logger.Println("test")
	})

	t.Run("stdLogger", func(t *testing.T) {
		var logger Logger = &stdLogger{}
		// Should not panic
		logger.Printf(testMessage, "message")
		logger.Print("test")
		logger.Println("test")
	})

	t.Run("mockLogger", func(t *testing.T) {
		mock := &mockLogger{}
		var logger Logger = mock

		logger.Printf(testMessage, "message")
		logger.Print("test")
		logger.Println("test")

		output := mock.buf.String()
		if !strings.Contains(output, "Printf") {
			t.Error("Expected Printf in output")
		}
		if !strings.Contains(output, "Print\n") {
			t.Error("Expected Print in output")
		}
		if !strings.Contains(output, "Println\n") {
			t.Error("Expected Println in output")
		}
	})
}

// TestServerLogger verifies that the Server.log() method works correctly
func TestServerLogger(t *testing.T) {
	t.Run("DefaultLogger", func(t *testing.T) {
		// Create a server with no Logger configured
		s := &Server{}
		logger := s.log()

		if logger == nil {
			t.Error(testExpectedNonNil)
		}

		// Should return the default logger instance
		if logger != defaultLoggerInstance {
			t.Error(testExpectedDefault)
		}

		// Default should be silent (DiscardLogger) per Go library conventions
		if _, ok := logger.(*DiscardLogger); !ok {
			t.Error(testExpectedDiscard)
		}
	})

	t.Run("CustomLogger", func(t *testing.T) {
		// Create a server with a custom logger
		customLogger := &mockLogger{}
		s := &Server{
			Configuration: Configuration{
				Logger: customLogger,
			},
		}

		logger := s.log()

		if logger == nil {
			t.Error(testExpectedNonNil)
		}

		// Should return the custom logger
		if logger != customLogger {
			t.Error(testExpectedCustom)
		}
	})

	t.Run("DiscardLogger", func(t *testing.T) {
		// Create a server with a discard logger
		discardLogger := &DiscardLogger{}
		s := &Server{
			Configuration: Configuration{
				Logger: discardLogger,
			},
		}

		logger := s.log()

		if logger == nil {
			t.Error(testExpectedNonNil)
		}

		// Should return the discard logger
		if logger != discardLogger {
			t.Error(expectedDiscardLogger)
		}

		// Should not panic when called
		logger.Printf(testMessage, "message")
		logger.Print("test")
		logger.Println("test")
	})
}

// TestConfigurationWithLogger verifies that Configuration can be created with a Logger
func TestConfigurationWithLogger(t *testing.T) {
	t.Run("NilLogger", func(t *testing.T) {
		config := Configuration{
			Logger: nil,
		}

		if config.Logger != nil {
			t.Error("Expected nil logger")
		}
	})

	t.Run("DiscardLogger", func(t *testing.T) {
		discardLogger := &DiscardLogger{}
		config := Configuration{
			Logger: discardLogger,
		}

		if config.Logger == nil {
			t.Error(testExpectedNonNil)
		}

		if config.Logger != discardLogger {
			t.Error(expectedDiscardLogger)
		}
	})

	t.Run("CustomLogger", func(t *testing.T) {
		customLogger := &mockLogger{}
		config := Configuration{
			Logger: customLogger,
		}

		if config.Logger == nil {
			t.Error(testExpectedNonNil)
		}

		if config.Logger != customLogger {
			t.Error(testExpectedCustom)
		}
	})
}
