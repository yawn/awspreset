# AWS password reset (`aswspreset`)

`aswspreset` is a library to perform AWS root user password resets.

## Examples

### Request a password reset

```
session, err := awspreset.New()

if err != nil {
  panic(err)
}

if err := session.ResetRequest(
	"root@example.com",
	awspreset.Terminal,
); err != nil {
	panic(err)
}
```

This should trigger a mail to `root@example.com`. Note that the error handling around wrong email addresses is not explicit at the moment.

### Set the new password

Extract the mail from your mailbox and put the link into the first parameter of the `ResetResponse` call.

```
session, err := awspreset.New()

if err != nil {
  panic(err)
}

if err := session.ResetResponse(
  "https://signin.aws.amazon.com/resetpassword?type=RootUser&token=...&key=...",
  "Th1s-Is-My-New-Password!",
); err != nil {
  panic(err)
}
```
