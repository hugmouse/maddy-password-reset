![Maddy password reset service logo](https://user-images.githubusercontent.com/44648612/218335570-cdb3ba2f-4ff9-43ee-bd43-f892c644b153.png)

# Maddy password reset service

Runs an HTTP server that serves password reset form.

Still Work In Progress! And so no LICENSE file is provided. It will be here eventually.

## Installation

For the time being, you have to compile it yourself. 
In the future there will be prebuilt binaries.

### Requirements

- Go
- Maddy

To build this project install `Go` and execute this:
```shell
go build ./main.go
```

Make sure to configure it first! First compilation will take moderate amount of time.

## Configuration

By default, the web server starts on `:1323'. Make sure you hide it behind a reverse proxy.

You will probably need to edit the `reset.gohtml` template to suit your needs.
For now, it contains a reset page in Russian for my hobby mail service.

The only way to change the configuration is to change the consts in the `main.go` file:

- `MaddyPath` - path to maddy's database, e.g.: `/var/lib/maddy/credentials.db`
- `HostingURL` - your domain name, for example: `http://localhost:1323/`
- `SMTPMailUsername` - your full email address, for example: `robot@local.host`
- `SMTPMailPassword` - your mailbox password
- `SMTPMailHostname` - your mail hostname, for example: `mx1.local.host`
- `MXServer` - your mail `MX` entry + `PORT`, for example: `mx1.local.host:587`
- `EmailFrom` - the `$FROM` section of an EmailTemplate, for example: `robot@local.host`
- `EmailSubject` - the `$SUBJECT` section of an EmailTemplate
- `EmailMessage` - the `$MESSAGE` section of an EmailTemplate. Remember to provide a password reset link for a user `$RESET_LINK`. For example: `Here's your reset link: $RESET_LINK\r\n`
- `EmailTemplate`- your reset email message
- `HTTPServerPort` - HTTP server port

`EmailTemplate` example:

```text
"To: $TO\r\n" +
"From: $FROM\r\n" +
"Content-Type: text/plain; charset=UTF-8\r\n" +
"Subject: $SUBJECT\r\n" +
"\r\n" +
"$MESSAGE\r\n"
```