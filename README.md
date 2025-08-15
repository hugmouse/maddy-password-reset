![Project Banner](https://user-images.githubusercontent.com/44648612/218335570-cdb3ba2f-4ff9-43ee-bd43-f892c644b153.png)

# Maddy Password Reset Service

Runs an HTTP server that serves a password reset form. 
It should be installed on the same server where Maddy is running.

Essentially, this is a simple web-based wrapper for Maddy's CLI
that you can customize to your specific case.

## How It Works

The service provides two ways to change passwords:

1. **Password Reset**: Sends a reset link via email
2. **Password Change**: Allows users to change their password using their current password

Both methods use the `maddy creds password -p` command to change passwords. Password verification retrieves the bcrypt hash from Maddy's database and verifies it directly.

### Use Cases

- **Password Reset**: User forgot their password and needs to reset it via email
    - This is more for the case when you have an active email session, but want to change your current password via special reset link
- **Password Change**: User knows their current password and wants to change it directly
    - For example, you registered a user, and the user wants to change their password

## Installation

For the time being, you need to compile it yourself.

### Requirements

- Go
- Maddy (on the server, we need its CLI)

To build this project, install `Go` and execute the following command:

```shell
go build ./main.go
```

Make sure to configure it first! The first compilation will take a moderate amount of time.

## Configuration

By default, the web server starts on `:1323`. Make sure you hide it behind a reverse proxy.

### Available translations

Templates are available in Russian and English languages.

To use English, replace references to `.gohtml` with `.en.gohtml`.

### Available Routes

Pages do not rely on JavaScript, so you can trigger them via Curl or some other client.

- **Password Reset**:
  - `GET /reset` - Display password reset form
  - `POST /reset` - Submit email for reset link
  - `GET /reset/:token` - Display new password form (from email link)  
  - `POST /reset/:token` - Submit new password

- **Password Change**:
  - `GET /change` - Display password change form
  - `POST /change` - Submit current and new passwords

### Templates

You will probably need to edit the templates to suit your needs:

- **Password Reset**: `reset.gohtml` (Russian), `reset.en.gohtml` (English)
- **Password Change**: `change.gohtml` (Russian), `change.en.gohtml` (English)

By default, the reset templates are configured for Russian, but English templates are also available.

The only way to change the configuration is to modify the constants in the `main.go` file:

- `MaddyPath` – Path to Maddy's database, e.g., `/var/lib/maddy/credentials.db`
- `HostingURL` – Your domain name, for example: `http://localhost:1323/`
- `SMTPMailUsername` – Your full email address, for example: `robot@local.host`
- `SMTPMailPassword` – Your mailbox password
- `SMTPMailHostname` – Your mail hostname, for example: `mx1.local.host`
- `MXServer` – Your mail `MX` entry and `PORT`, for example: `mx1.local.host:587`
- `EmailFrom` – The `$FROM` section of an email template, for example: `robot@local.host`
- `EmailSubject` – The `$SUBJECT` section of an email template
- `EmailMessage` – The `$MESSAGE` section of an email template. Remember to provide a password reset link for the user using `$RESET_LINK`. For example: `Here's your reset link: $RESET_LINK\r\n`
- `EmailTemplate` – Your reset email message
- `HTTPServerPort` – HTTP server port

### `EmailTemplate` Example

```text
"To: $TO\r\n" +
"From: $FROM\r\n" +
"Content-Type: text/plain; charset=UTF-8\r\n" +
"Subject: $SUBJECT\r\n" +
"\r\n" +
"$MESSAGE\r\n"
```
