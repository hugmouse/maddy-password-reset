![Project Banner](https://user-images.githubusercontent.com/44648612/218335570-cdb3ba2f-4ff9-43ee-bd43-f892c644b153.png)

# Maddy Password Reset Service

Runs an HTTP server that serves a password reset form. 
It should be installed on the same server where Maddy is running.

## How It Works

It runs the `maddy creds password -p` command to change a user's password.

### Use Cases

- You are currently logged into your mailbox and want to reset the password.
    - For example, you registered a user, and the user wants to change their password.

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

You will probably need to edit the `reset.gohtml` template to suit your needs. 
For now, it contains a reset page in Russian for my hobby mail service.

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
