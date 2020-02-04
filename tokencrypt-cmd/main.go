package main

import (
	"bufio"
	"fmt"
	"github.com/3ncr/tokencrypt"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter secret part 1: ")
	part1, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalln("Error reading secret:", err.Error())
	}
	fmt.Println("")

	fmt.Print("Enter secret part 2: ")
	part2, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalln("Error reading secret:", err.Error())
	}
	fmt.Println("")

	var iter int
	for {
		fmt.Print("Enter iterations number (1000): ")
		iterstr, _ := reader.ReadString('\n')
		fmt.Println("")

		iterstr = strings.TrimSpace(iterstr)
		if iterstr == "" {
			iter = 1000
			break
		}

		iterint, err := strconv.Atoi(iterstr)
		if err != nil {
			fmt.Println("error parsing integer", err.Error())
			continue
		}
		iter = iterint
		break
	}

	tc, err := tokencrypt.NewTokenCrypt([]byte(part1), []byte(part2), iter)
	if err != nil {
		log.Fatalln("Error creating tokencrypt:", err.Error())
	}

	fmt.Println("Interactive session: press Ctrl-D or type q to quit")
	for {

		fmt.Print("plain or encrypted text> ")
		text, err := reader.ReadString('\n')
		text = strings.TrimSpace(text)

		if text == "q" || err != nil {
			break
		}
		dec, err := tc.DecryptIf3ncr(text)
		if err != nil {
			fmt.Println("decryption error:", err.Error())
			continue
		}
		if dec != text {
			fmt.Println("decrypted plaintext:", dec)
			continue
		}

		enc, err := tc.Encrypt3ncr(text)

		if err != nil {
			fmt.Println("encryption error:", err.Error())
			continue
		}
		fmt.Println("encrypted value:", enc)

	}

}
