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

const (
	// MaddyPath is path to your Maddy credentials database
	//
	// FYI, Maddy's password database by default is "/var/lib/maddy/credentials.db"
	MaddyPath = ""

	// HostingURL is your domain name,
	// for example: `http://localhost:1323/`
	HostingURL = ""

	// SMTPMailUsername is your full mail address,
	// for example: `robot@local.host`
	SMTPMailUsername = ""

	// SMTPMailPassword is your mailbox password
	SMTPMailPassword = ""

	// SMTPMailHostname is your mail hostname,
	// for example: `mx1.local.host`
	SMTPMailHostname = ""

	// MXServer is your mail `MX` record + `PORT`,
	// for example: `mx1.local.host:587`
	MXServer = ""

	// EmailFrom is a EmailTemplate's "$FROM" section
	EmailFrom = ""
	// EmailSubject is a EmailTemplate's "$SUBJECT" section
	EmailSubject = ""
	// EmailMessage is a EmailTemplate's "$MESSAGE" section
	//
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

	// DebugBypassMailSending if true, will not send any emails and will print reset link to the console
	DebugBypassMailSending = true
)

const (
	// TokenAlphabet is created for random string creation, see randomString() function
	TokenAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func randomString(length int) string {
	l := big.NewInt(int64(len(TokenAlphabet)))
	res := new(strings.Builder)
	for i := 0; i < length; i++ {
		n, err := cryptorand.Int(cryptorand.Reader, l)
		if err != nil {
			panic(err)
		}

		res.WriteByte(TokenAlphabet[n.Int64()])
	}

	return res.String()
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func isValidEmailAddress(email string) error {
	// Parse the email address using addressparser
	mail, err := mail.ParseAddress(email)
	if err != nil {
		return err
	}

	// Check if the parsed address is not nil and has a valid email format
	if mail == nil || mail.Address == "" {
		log.Println("[AddressParser]: Invalid Email Address: %v")
		return err
	}

	return nil
}

func main() {
	var auth smtp.Auth
	if !DebugBypassMailSending {
		log.Println("[EmailMessage const] Checking your template")
		if !strings.Contains(EmailMessage, "$RESET_LINK") {
			log.Fatalln("[EmailMessage const] Your message template does not contain $RESET_LINK, so user can't reset his password!")
		}

		log.Println("[EmailTemplate const] Checking your template")
		if !strings.Contains(EmailTemplate, "$TO") {
			log.Fatalln("[EmailTemplate const] Your template does not contain $TO, make sure to add it.")
		}

		if !strings.Contains(EmailTemplate, "$FROM") {
			log.Fatalln("[EmailTemplate const] Your template does not contain $FROM, make sure to add it.")
		}

		if !strings.Contains(EmailTemplate, "$SUBJECT") {
			log.Fatalln("[EmailTemplate const] Your template does not contain $SUBJECT, make sure to add it, so user can see a message preview.")
		}

		if !strings.Contains(EmailTemplate, "$MESSAGE") {
			log.Fatalln("[EmailTemplate const] Your template does not contain $MESSAGE, make sure to add it.")
		}

		// Set up authentication information.
		auth = smtp.PlainAuth("", SMTPMailUsername, SMTPMailPassword, SMTPMailHostname)
	} else {
		log.Println("[SMTP] Debug mode enabled, not checking email template")
	}

	log.Println("[Sqlite] Loading Maddy's credentials database")
	db, err := sql.Open("sqlite", MaddyPath)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("[Cache] Registering cache for password resets")
	passwordResetCache := cache.New(CacheTime)

	log.Println("[Echo] Initializing echo web server")
	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.LoggerWithConfig(
		middleware.LoggerConfig{
			Format:           `${time_custom} [Echo] ${latency_human} ${method} ${uri} - Error = ${error} - ${remote_ip} "${user_agent}"` + "\n",
			CustomTimeFormat: "2006/01/02 15:04:05",
		}))
	e.Use(middleware.Recover())

	log.Println("[Echo] Registering Go templates")
	t := template.Must(template.ParseFS(templates.Templates, "*.gohtml"))
	e.Renderer = &Template{
		t,
	}

	e.GET("/reset", func(c echo.Context) error {
		return c.Render(http.StatusOK, "reset.gohtml", nil)
	})

	e.POST("/reset", func(c echo.Context) error {
		mail := c.FormValue("email")
		err = isValidEmailAddress(mail)
		if err != nil {
			log.Println("[AddressParser]: Invalid mail address: ", err)
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid mail address: %v", err))
		}
		go func() {
			// Check if there is already a password reset
			_, exists := passwordResetCache.Get(mail)
			if exists {
				log.Printf("[Cache] Mail %q already exists in cache, ignoring\n", mail)
				return
			}

			// Check if it's exists in Maddy db
			// It will return an error is there is no user found
			var password string
			err = db.QueryRow("SELECT value FROM passwords WHERE key = ?", mail).Scan(&password)
			if err != nil {
				log.Println("[Sqlite] An error occurred while trying to get password from Maddy database:", err)
				return
			}

			// Generating an unique key
			random := randomString(10)
			passwordResetCache.Set(random, mail, CacheTime)

			// Connect to the server, authenticate, set the sender and recipient,
			// and send the email all in one step.
			to := []string{mail}

			if !DebugBypassMailSending {
				msg := strings.ReplaceAll(EmailTemplate, "$TO", mail)
				msg = strings.ReplaceAll(msg, "$FROM", EmailFrom)
				msg = strings.ReplaceAll(msg, "$SUBJECT", EmailSubject)
				msg = strings.ReplaceAll(msg, "$MESSAGE", EmailMessage)
				msg = strings.ReplaceAll(msg, "$RESET_LINK", HostingURL+"reset/"+random)

				err := smtp.SendMail(MXServer, auth, SMTPMailUsername, to, []byte(msg))
				if err != nil {
					log.Println("[SMTP] Failed to send mail - ", err)
					return
				}
			} else {
				log.Println("[SMTP] Debug mode enabled, not sending email")
				log.Println("[SMTP] Reset link:", HostingURL+"reset/"+random)
			}
		}()

		return c.Render(http.StatusOK, "reset.gohtml", map[string]any{
			"Sent": true,
		})
	})

	e.GET("/reset/:key", func(c echo.Context) error {
		key := c.Param("key")
		_, exists := passwordResetCache.Get(key)
		if !exists {
			return c.Redirect(http.StatusTemporaryRedirect, "/reset")
		}
		return c.Render(http.StatusOK, "reset.gohtml", map[string]any{
			"UniqueLinkTriggered": true,
		})
	})

	e.POST("/reset/:key", func(c echo.Context) error {
		key := c.Param("key")
		password := c.FormValue("password")
		mail, exists := passwordResetCache.Get(key)
		if exists {
			passwordResetCache.Delete(key)
		}

		maddyExecCommand := exec.Command("maddy", "creds", "password", "-p", password, mail.(string))
		err = maddyExecCommand.Run()
		if err != nil {
			log.Println("[maddyExecCommand] Failed to execute Maddy's password reset command - ", err)
			return err
		}

		return c.String(http.StatusOK, "All good! Your password is now changed.")
	})

	log.Println("[echo] Starting Echo web server")
	e.Logger.Fatal(e.Start(":" + strconv.Itoa(HTTPServerPort)))
}
