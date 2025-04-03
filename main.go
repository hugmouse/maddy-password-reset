/*
Maddy Password Reset - Simple password reset web service for Maddy Mail Server
Copyright © 2023 Iaroslav Angliuster <me@mysh.dev>, Maddy Password Reset contributors
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	cryptorand "crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"github.com/akyoto/cache"
	"github.com/hugmouse/maddy-password-reset/templates"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"html/template"
	"io"
	"log"
	"math/big"
	_ "modernc.org/sqlite"
	"net/http"
	"net/mail"
	"net/smtp"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------
// Configuration
// Make sure to set these constants before running the program
// ---------------------------------------------------------------
const (
	// MaddyPath is path to your Maddy credentials database
	// FYI, Maddy's password database by default is "/var/lib/maddy/credentials.db"
	MaddyPath = "maddy.db" // MUST be set

	// HostingURL is your domain name, including scheme and trailing slash,
	// for example: `http://localhost:1323/` or `https://example.com/`
	HostingURL = "http://localhost:1323/" // MUST be set

	// SMTPMailUsername is your full mail address,
	// for example: `robot@local.host`
	SMTPMailUsername = "" // MUST be set (unless DebugBypassMailSending is true)

	// SMTPMailPassword is your mailbox password
	SMTPMailPassword = "" // MUST be set (unless DebugBypassMailSending is true)

	// SMTPMailHostname is your mail hostname,
	// for example: `mx1.local.host`
	SMTPMailHostname = "" // MUST be set (unless DebugBypassMailSending is true)

	// MXServer is your mail `MX` record + `PORT`,
	// for example: `mx1.local.host:587`
	MXServer = "" // MUST be set (unless DebugBypassMailSending is true)

	// EmailFrom is a EmailTemplate's "$FROM" section
	EmailFrom = "" // MUST be set (unless DebugBypassMailSending is true)
	// EmailSubject is a EmailTemplate's "$SUBJECT" section
	EmailSubject = "" // MUST be set (unless DebugBypassMailSending is true)
	// EmailMessage is a EmailTemplate's "$MESSAGE" section
	// Remember to provide a password reset link to a user ($RESET_LINK)
	EmailMessage = "Here's your reset link: $RESET_LINK\r\n"
	// EmailTemplate is your reset mail message
	EmailTemplate = "To: $TO\r\n" +
		"From: $FROM\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"Subject: $SUBJECT\r\n" +
		"\r\n" +
		"$MESSAGE"

	// CacheTime is the duration that your password reset link will last
	CacheTime = 15 * time.Minute

	// HTTPServerPort is an HTTP server port
	HTTPServerPort = 1323

	// DebugBypassMailSending - if true, skips SMTP checks and sending, logs reset link instead.
	DebugBypassMailSending = true
)

// ---------------------------------------------------------------
// Constants for random string generator
// ---------------------------------------------------------------
const (
	TokenAlphabet      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	RandomStringLength = 10
)

// ---------------------------------------------------------------
// Log Message Constants
// ---------------------------------------------------------------
const (
	// Configuration Validation
	logMsgConfigValidationStart               = "[Startup] Validating configuration..."
	logMsgConfigMaddyPathEmpty                = "[Config] MaddyPath constant cannot be empty."
	logMsgConfigHostingURLEmpty               = "[Config] HostingURL constant cannot be empty."
	logMsgConfigHostingURLSlashFmt            = "[Config] HostingURL must end with a trailing slash '/'. Current value: %s"
	logMsgConfigSmtpCheckStart                = "[Config] Checking SMTP and Email Template configuration (DebugBypassMailSending is false)"
	logMsgConfigSmtpUsernameEmpty             = "[Config] SMTPMailUsername constant cannot be empty when DebugBypassMailSending is false."
	logMsgConfigSmtpPasswordEmpty             = "[Config] SMTPMailPassword constant cannot be empty when DebugBypassMailSending is false."
	logMsgConfigSmtpHostnameEmpty             = "[Config] SMTPMailHostname constant cannot be empty when DebugBypassMailSending is false."
	logMsgConfigMxServerEmpty                 = "[Config] MXServer constant cannot be empty when DebugBypassMailSending is false."
	logMsgConfigEmailFromEmpty                = "[Config] EmailFrom constant cannot be empty when DebugBypassMailSending is false."
	logMsgConfigEmailSubjectEmpty             = "[Config] EmailSubject constant cannot be empty when DebugBypassMailSending is false."
	logMsgConfigEmailMsgResetLinkCheck        = "[EmailMessage const] Checking your template for $RESET_LINK"
	logMsgConfigEmailMsgResetLinkMissing      = "[EmailMessage const] Your message template does not contain $RESET_LINK, so user can't reset his password!"
	logMsgConfigEmailTplPlaceholdersCheck     = "[EmailTemplate const] Checking your template placeholders ($TO, $FROM, $SUBJECT, $MESSAGE)"
	logMsgConfigEmailTplPlaceholderMissingFmt = "[EmailTemplate const] Your template does not contain %s, make sure to add it."
	logMsgConfigSmtpCheckSkipped              = "[Config] DebugBypassMailSending is true. Skipping SMTP and Email Template configuration checks."
	logMsgConfigCacheTimeInvalid              = "[Config] CacheTime must be a positive duration."
	logMsgConfigHttpPortInvalid               = "[Config] HTTPServerPort must be a valid port number (1-65535)."

	// SMTP
	logMsgSmtpAuthSetup           = "[SMTP] Configuring SMTP authentication."
	logMsgSmtpAuthSkipped         = "[SMTP] Debug mode enabled, skipping SMTP authentication setup."
	logMsgSmtpSendFailedFmt       = "[SMTP] Failed to send password reset email to %q: %v"
	logMsgSmtpSendSuccessFmt      = "[SMTP] Password reset email successfully sent to %q"
	logMsgSmtpDebugSendSkippedFmt = "[SMTP] Debug mode enabled. Would send reset email to %q."
	logMsgSmtpDebugResetLinkFmt   = "[SMTP] Reset link for %q: %s"

	// Sqlite
	logMsgDbLoadingFmt      = "[Sqlite] Loading Maddy's credentials database from: %s"
	logMsgDbOpenFailedFmt   = "[Sqlite] Failed to open database: %v"
	logMsgDbClosing         = "[Sqlite] Closing database connection."
	logMsgDbCloseErrorFmt   = "[Sqlite] Error closing database: %v"
	logMsgDbPingFailedFmt   = "[Sqlite] Failed to connect to database: %v"
	logMsgDbPingSuccess     = "[Sqlite] Database connection successful."
	logMsgDbUserNotFoundFmt = "[Sqlite] User email %q not found in Maddy database. No reset link generated."
	logMsgDbQueryErrorFmt   = "[Sqlite] Error querying Maddy database for user %q: %v"

	// Cache
	logMsgCacheRegisterFmt     = "[Cache] Registering cache for password resets with expiry: %v"
	logMsgCacheResetPendingFmt = "[Cache] Password reset request for %q already pending, ignoring new request."

	// Echo server
	logMsgEchoInit           = "[Echo] Initializing echo web server"
	logMsgEchoTplRegister    = "[Echo] Registering Go templates"
	logMsgEchoStartFmt       = "[Echo] Starting Echo web server on %s"
	logMsgEchoStartFailedFmt = "[Echo] Failed to start server: %v"

	// Handlers
	logMsgHandlerPostResetInvalidEmailFmt = "[Handler POST /reset] Invalid email address provided '%s': %v"
	logMsgHandlerGetKeyEmpty              = "[Handler GET /reset/:key] Received empty key."
	logMsgHandlerGetKeyInvalidFmt         = "[Handler GET /reset/:key] Invalid or expired key provided: %s"
	logMsgHandlerPostKeyEmpty             = "[Handler POST /reset/:key] Received empty key."
	logMsgHandlerPostKeyEmptyPassword     = "[Handler POST /reset/:key] Received empty password."
	logMsgHandlerPostKeyInvalidFmt        = "[Handler POST /reset/:key] Invalid or expired key submitted: %s"
	logMsgHandlerPostKeyCacheTypeFmt      = "[Handler POST /reset/:key] Value retrieved from cache for key %s is not a string: %T"

	// Reset Process
	logMsgResetTokenGeneratedFmt = "[Reset] Generated reset token %s for user %s. Link: %s"

	// Maddy Command Execution
	logMsgMaddyExecAttemptFmt = "[Maddy] Attempting to reset password for user %s via maddy command."
	logMsgMaddyExecFailedFmt  = "[Maddy] Failed to execute Maddy password reset command for %s: %v. Output: %s"
	logMsgMaddyExecSuccessFmt = "[Maddy] Successfully reset password for user %s. Output: %s"

	// Other
	logMsgRandNumGenFailedCriticalFmt = "CRITICAL: Failed to generate random number: %v"
)

func randomString(length int) string {
	l := big.NewInt(int64(len(TokenAlphabet)))
	res := new(strings.Builder)
	res.Grow(length)
	for i := 0; i < length; i++ {
		n, err := cryptorand.Int(cryptorand.Reader, l)
		if err != nil {
			log.Fatalf(logMsgRandNumGenFailedCriticalFmt, err)
		}
		res.WriteByte(TokenAlphabet[n.Int64()])
	}
	return res.String()
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func isValidEmailAddress(email string) error {
	if email == "" {
		return errors.New("email address cannot be empty")
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email format: %w", err)
	}

	if !strings.Contains(addr.Address, "@") {
		return errors.New("invalid email format: missing @ symbol")
	}

	return nil
}

func validateConfiguration() {
	if MaddyPath == "" {
		log.Fatalln(logMsgConfigMaddyPathEmpty)
	}

	if HostingURL == "" {
		log.Fatalln(logMsgConfigHostingURLEmpty)
	}

	if !strings.HasSuffix(HostingURL, "/") {
		log.Fatalf(logMsgConfigHostingURLSlashFmt, HostingURL)
	}

	if !DebugBypassMailSending {
		log.Println(logMsgConfigSmtpCheckStart)
		if SMTPMailUsername == "" {
			log.Fatalln(logMsgConfigSmtpUsernameEmpty)
		}
		if SMTPMailPassword == "" {
			log.Fatalln(logMsgConfigSmtpPasswordEmpty)
		}
		if SMTPMailHostname == "" {
			log.Fatalln(logMsgConfigSmtpHostnameEmpty)
		}
		if MXServer == "" {
			log.Fatalln(logMsgConfigMxServerEmpty)
		}
		if EmailFrom == "" {
			log.Fatalln(logMsgConfigEmailFromEmpty)
		}
		if EmailSubject == "" {
			log.Fatalln(logMsgConfigEmailSubjectEmpty)
		}

		log.Println(logMsgConfigEmailMsgResetLinkCheck)
		if !strings.Contains(EmailMessage, "$RESET_LINK") {
			log.Fatalln(logMsgConfigEmailMsgResetLinkMissing)
		}

		log.Println(logMsgConfigEmailTplPlaceholdersCheck)
		requiredPlaceholders := []string{"$TO", "$FROM", "$SUBJECT", "$MESSAGE"}
		for _, placeholder := range requiredPlaceholders {
			if !strings.Contains(EmailTemplate, placeholder) {
				log.Fatalf(logMsgConfigEmailTplPlaceholderMissingFmt, placeholder)
			}
		}
	} else {
		log.Println(logMsgConfigSmtpCheckSkipped)
	}

	if CacheTime <= 0 {
		log.Fatalln(logMsgConfigCacheTimeInvalid)
	}

	if HTTPServerPort <= 0 || HTTPServerPort > 65535 {
		log.Fatalln(logMsgConfigHttpPortInvalid)
	}
}

func main() {
	log.Println(logMsgConfigValidationStart)
	validateConfiguration()

	var auth smtp.Auth
	if !DebugBypassMailSending {
		log.Println(logMsgSmtpAuthSetup)
		auth = smtp.PlainAuth("", SMTPMailUsername, SMTPMailPassword, SMTPMailHostname)
	} else {
		log.Println(logMsgSmtpAuthSkipped)
	}

	log.Printf(logMsgDbLoadingFmt, MaddyPath)
	db, err := sql.Open("sqlite", MaddyPath)
	if err != nil {
		log.Fatalf(logMsgDbOpenFailedFmt, err)
	}
	defer func() {
		log.Println(logMsgDbClosing)
		if err := db.Close(); err != nil {
			log.Printf(logMsgDbCloseErrorFmt, err)
		}
	}()

	if err := db.Ping(); err != nil {
		log.Fatalf(logMsgDbPingFailedFmt, err)
	}
	log.Println(logMsgDbPingSuccess)

	log.Printf(logMsgCacheRegisterFmt, CacheTime)
	passwordResetCache := cache.New(CacheTime)

	log.Println(logMsgEchoInit)
	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.LoggerWithConfig(
		middleware.LoggerConfig{
			Format:           `${time_custom} [Echo] ${latency_human} ${method} ${uri} - Status=${status} Error="${error}" RemoteIP=${remote_ip} UserAgent="${user_agent}"` + "\n",
			CustomTimeFormat: "2006/01/02 15:04:05",
		}))
	e.Use(middleware.Recover())

	log.Println(logMsgEchoTplRegister)
	t := template.Must(template.ParseFS(templates.Templates, "*.gohtml"))
	e.Renderer = &Template{
		templates: t,
	}

	e.GET("/reset", func(c echo.Context) error {
		return c.Render(http.StatusOK, "reset.gohtml", nil)
	})

	e.POST("/reset", func(c echo.Context) error {
		email := c.FormValue("email")
		if err := isValidEmailAddress(email); err != nil {
			log.Printf(logMsgHandlerPostResetInvalidEmailFmt, email, err)
			return c.Render(http.StatusBadRequest, "reset.gohtml", map[string]any{
				"Error": "Invalid email address format provided.",
			})
		}

		go func(userEmail string) {

			// Check if there is already a pending password reset for this email
			_, exists := passwordResetCache.Get(userEmail)
			if exists {
				log.Printf(logMsgCacheResetPendingFmt, userEmail)
				return
			}

			// Check if user exists in Maddy DB
			var dummy int
			dbErr := db.QueryRow("SELECT 1 FROM passwords WHERE key = ?", userEmail).Scan(&dummy)

			if dbErr != nil {
				if errors.Is(dbErr, sql.ErrNoRows) {
					log.Printf(logMsgDbUserNotFoundFmt, userEmail)
				} else {
					log.Printf(logMsgDbQueryErrorFmt, userEmail, dbErr)
				}
				return
			}

			token := randomString(RandomStringLength)
			passwordResetCache.Set(token, userEmail, CacheTime)
			passwordResetCache.Set(userEmail, token, CacheTime)

			resetLink := HostingURL + "reset/" + token
			log.Printf(logMsgResetTokenGeneratedFmt, token, userEmail, resetLink)

			if !DebugBypassMailSending {
				msg := strings.ReplaceAll(EmailTemplate, "$TO", userEmail)
				msg = strings.ReplaceAll(msg, "$FROM", EmailFrom)
				msg = strings.ReplaceAll(msg, "$SUBJECT", EmailSubject)

				messageBody := strings.ReplaceAll(EmailMessage, "$RESET_LINK", resetLink)
				msg = strings.ReplaceAll(msg, "$MESSAGE", messageBody)

				to := []string{userEmail}
				smtpErr := smtp.SendMail(MXServer, auth, SMTPMailUsername, to, []byte(msg))
				if smtpErr != nil {
					log.Printf(logMsgSmtpSendFailedFmt, userEmail, smtpErr)
					// Clean up cache if sending failed
					passwordResetCache.Delete(token)
					passwordResetCache.Delete(userEmail)
					return
				}
				log.Printf(logMsgSmtpSendSuccessFmt, userEmail)
			} else {
				log.Printf(logMsgSmtpDebugSendSkippedFmt, userEmail)
				log.Printf(logMsgSmtpDebugResetLinkFmt, userEmail, resetLink)
			}
		}(email)

		// Always return success to the user to prevent email enumeration
		return c.Render(http.StatusOK, "reset.gohtml", map[string]any{
			"Sent": true, // Indicates request received, not necessarily email sent successfully
		})
	})

	e.GET("/reset/:key", func(c echo.Context) error {
		key := c.Param("key")
		if key == "" {
			log.Println(logMsgHandlerGetKeyEmpty)
			return c.Redirect(http.StatusTemporaryRedirect, "/reset")
		}

		_, exists := passwordResetCache.Get(key)
		if !exists {
			log.Printf(logMsgHandlerGetKeyInvalidFmt, key)
			return c.Render(http.StatusNotFound, "reset.gohtml", map[string]any{
				"Error": "This password reset link is invalid or has expired.",
			})
		}

		return c.Render(http.StatusOK, "reset.gohtml", map[string]any{
			"UniqueLinkTriggered": true,
			"Key":                 key,
		})
	})

	e.POST("/reset/:key", func(c echo.Context) error {
		key := c.Param("key")
		password := c.FormValue("password")

		if key == "" {
			log.Println(logMsgHandlerPostKeyEmpty)
			return c.Render(http.StatusBadRequest, "reset.gohtml", map[string]any{
				"Error": "Reset key is missing.",
			})
		}
		if password == "" {
			log.Println(logMsgHandlerPostKeyEmptyPassword)
			return c.Render(http.StatusBadRequest, "reset.gohtml", map[string]any{
				"UniqueLinkTriggered": true,
				"Key":                 key,
				"Error":               "Password cannot be empty.",
			})
		}

		emailVal, exists := passwordResetCache.Get(key)
		if !exists {
			log.Printf(logMsgHandlerPostKeyInvalidFmt, key)
			return c.Render(http.StatusNotFound, "reset.gohtml", map[string]any{
				"Error": "This password reset link is invalid or has expired. Please request a new one.",
			})
		}

		email, ok := emailVal.(string)
		if !ok {
			log.Printf(logMsgHandlerPostKeyCacheTypeFmt, key, emailVal)
			passwordResetCache.Delete(key)
			passwordResetCache.Delete(email)
			return c.Render(http.StatusInternalServerError, "reset.gohtml", map[string]any{
				"Error": "An internal error occurred. Please try again.",
			})
		}

		// Invalidate stuff
		passwordResetCache.Delete(key)
		passwordResetCache.Delete(email)

		log.Printf(logMsgMaddyExecAttemptFmt, email)
		maddyExecCommand := exec.Command("maddy", "creds", "password", "-p", password, email)
		output, execErr := maddyExecCommand.CombinedOutput()

		if execErr != nil {
			log.Printf(logMsgMaddyExecFailedFmt, email, execErr, string(output))
			return c.Render(http.StatusInternalServerError, "reset.gohtml", map[string]any{
				"Error": "Failed to update password due to a server error.",
			})
		}

		log.Printf(logMsgMaddyExecSuccessFmt, email, string(output))
		return c.Render(http.StatusOK, "reset.gohtml", map[string]any{
			"Success": "Password successfully changed! You can now log in with your new password.",
		})
	})

	serverAddr := ":" + strconv.Itoa(HTTPServerPort)
	log.Printf(logMsgEchoStartFmt, serverAddr) // Use Printf for format string
	if err := e.Start(serverAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf(logMsgEchoStartFailedFmt, err)
	}
}
