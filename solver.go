package awspreset

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// CaptchaSolver is a function that solves captchas for password reset requests
type CaptchaSolver func(attempt int, url string) (string, error)

// Terminal is an interactive CaptchaSolver implemention with special iTerm2 support
var Terminal = func(attempt int, url string) (string, error) {

	fmt.Printf("solve captcha at %q (attempt %d)\n", url, attempt)

	iterm := os.Getenv("LC_TERMINAL") == "iTerm2"

	if iterm {

		res, err := http.Get(url)

		if err != nil {
			panic(err)
		}

		captcha, err := ioutil.ReadAll(res.Body)

		if err != nil {
			panic(err)
		}

		defer res.Body.Close()

		fmt.Printf("\033]1337;File=inline=1;width=400px;height=140px:%s\a\n", base64.StdEncoding.EncodeToString(captcha))

	}

	guess, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	guess = strings.TrimSuffix(guess, "\n")

	return guess, nil

}
