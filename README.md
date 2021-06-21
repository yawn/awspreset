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

## Enable MFA

Now login with new the new password and enable a [virtual MFA device](https://aws.amazon.com/iam/features/mfa/).

```
session, err := awspreset.New()

if err != nil {
  panic(err)
}

err = session.Login(
  "root@example.com",
  "Th1s-Is-My-New-Password!",
  awspreset.Terminal,
  nil,
)

if err != nil {
  panic(err)
}

mfa := awspreset.NewMFA(session)

res, err := mfa.EnableMFA()

if err != nil {
  panic(err)
}

res, err := mfa.EnableMFA()

if err != nil {
  panic(err)
}

fmt.Printf("MFA secrets %q", res.Base32StringSeed)

// start new

session, err = awspreset.New()

if err != nil {
  panic(err)
}

otp := func() string {

  codes, err := awspreset.TOTP(res.Base32StringSeed)

  if err != nil {
    panic(err)
  }

  log.Printf("log in with otp %s", codes[0])

  return codes[0]

}

err = session.Login(
  "root@example.com",
  "Th1s-Is-My-New-Password!",
  awspreset.Terminal,
  otp,
)

if err != nil {
  panic(err)
}
```
