package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// LogLevel defines the severity of the log
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	FATAL
)

// Logger represents a logger instance
type Logger struct {
	mu     sync.Mutex
	level  LogLevel
	output io.Writer
	file   *os.File
}

// Global logger instance
var globalLogger *Logger
var globalLoggerOnce sync.Once

// GetLogger returns the global logger instance
func GetLogger() *Logger {
	globalLoggerOnce.Do(func() {
		globalLogger = &Logger{
			level:  INFO,
			output: os.Stdout,
		}
	})
	return globalLogger
}

// WithLevel sets the log level
func (l *Logger) WithLevel(level LogLevel) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
	return l
}

// WithOutput sets the output destination (file or writer)
func (l *Logger) WithOutput(output io.Writer) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = output
	return l
}

// WithFileOutput sets the output to a file
func (l *Logger) WithFileOutput(filename string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		l.file.Close()
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	l.file = file
	l.output = file
	return nil
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level <= DEBUG {
		l.log(DEBUG, format, args...)
	}
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level <= INFO {
		l.log(INFO, format, args...)
	}
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level <= WARNING {
		l.log(WARNING, format, args...)
	}
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	if l.level <= ERROR {
		l.log(ERROR, format, args...)
	}
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(FATAL, format, args...)
	os.Exit(1)
}

// log is the internal logging function
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Get caller information
	_, file, line, ok := runtime.Caller(3) // Skip 3 levels to get actual caller
	if ok {
		file = filepath.Base(file) // Get just the filename
	}

	// Format timestamp
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Format log level
	levelStr := l.levelToString(level)

	// Format message
	message := fmt.Sprintf(format, args...)

	// Format the final log line
	logLine := fmt.Sprintf("[%s] [%s] [%s:%d] %s\n", timestamp, levelStr, file, line, message)

	// Write to output
	_, err := l.output.Write([]byte(logLine))
	if err != nil {
		// If we can't write to output, at least try to write to stderr
		fmt.Fprintf(os.Stderr, "Failed to write to log output: %v\n", err)
		fmt.Fprintf(os.Stderr, "%s", logLine)
	}

	// For standard output and error, force flush by calling Sync on the underlying file descriptor
	if l.output == os.Stdout {
		os.Stdout.Sync()
	} else if l.output == os.Stderr {
		os.Stderr.Sync()
	} else if flusher, ok := l.output.(interface{ Flush() error }); ok {
		flusher.Flush()
	} else if file, ok := l.output.(*os.File); ok {
		// For file output, sync to ensure content is written
		file.Sync()
	}
}

// levelToString converts log level to string
func (l *Logger) levelToString(level LogLevel) string {
	switch level {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARNING:
		return "WARNING"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Global helper functions using the global logger instance
func Debug(format string, args ...interface{}) {
	GetLogger().Debug(format, args...)
}

func Info(format string, args ...interface{}) {
	GetLogger().Info(format, args...)
}

func Warn(format string, args ...interface{}) {
	GetLogger().Warn(format, args...)
}

func Error(format string, args ...interface{}) {
	GetLogger().Error(format, args...)
}

func Fatal(format string, args ...interface{}) {
	GetLogger().Fatal(format, args...)
}

func SetLevel(level LogLevel) {
	GetLogger().WithLevel(level)
}

func SetOutput(output io.Writer) {
	GetLogger().WithOutput(output)
}

func SetFileOutput(filename string) error {
	return GetLogger().WithFileOutput(filename)
}
