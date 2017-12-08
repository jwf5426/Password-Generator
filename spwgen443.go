////////////////////////////////////////////////////////////////////////////////
//
//  File           : spwgen443.go
//  Description    : This is the implementaiton file for the spwgen443 password
//                   generator program.  See assignment details.
//
//  Collaborators  : James Frazier, Sahil Mishra, Danilem Colom, James Cunningham
//  Last Modified  : **TODO**: FILL ME IN
//

// Package statement
package main

// Imports
import (
	"fmt"
	"os"
	"math/rand"
	"strconv"
	"time"
	"github.com/pborman/getopt"
	"regexp"
	"bufio"
	"os/exec"
	// There will likely be several mode APIs you need
)

// Global data
var patternval string = `pattern (set of symbols defining password)

        A pattern consists of a string of characters "xxxxx",
        where the x pattern characters include:

          d - digit
          c - upper or lower case character
          l - lower case character
          u - upper case character
          w - random word from /usr/share/dict/words (or /usr/dict/words)
              note that w# will identify a word of length #, if possible
          s - special character in ~!@#$%^&*()-_=+{}[]:;/?<>,.|\

        Note: the pattern overrides other flags, e.g., -w`

// You may want to create more global variables

//
// Functions

// Up to you to decide which functions you want to add
func myOwnRNG() int64 {
	var rnd int64 = 0
	cmd := "od"

	args := []string{"-An", "-N8", "-td8", "/dev/urandom"}

	if urandom, err := exec.Command(cmd, args...).Output(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	} else {
		r := regexp.MustCompile("^[0-9-]+$").MatchString
		urandomStart := -1
		urandomEnd := 20
		j := 0
		for urandomStart == -1 && j < len(urandom) {
			if r(string(urandom[j])) {
					urandomStart = j
			}
			j = j + 1
		}

		if ranInt, err := strconv.Atoi(string(urandom[urandomStart:urandomEnd + 1])); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		} else {
			rnd = int64(ranInt)
		}
	}

	return rnd
}

func getDicWord(reqLen int) string {
	var words []string

	if dict, err := os.Open("/usr/share/dict/words"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	} else {
		defer dict.Close()

		scanner := bufio.NewScanner(dict)
		r := regexp.MustCompile("^[a-zA-Z]+$").MatchString

		for scanner.Scan() {
			switch reqLen {
			case -1:
				if r(scanner.Text()) {
					words = append(words,scanner.Text())
				}
			default:
				if r(scanner.Text()) && len(scanner.Text()) == reqLen {
					words = append(words,scanner.Text())
				}
			}
		}
	}

	if len(words) == 0 {
		fmt.Printf("No words in dictionary with length of %d\n", reqLen)
		os.Exit(-1)
	}
	return words[rand.Intn(len(words))]
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : generatePasword
// Description  : This is the function to generate the password.
//
// Inputs       : length - length of password
//                pattern - pattern of the file ("" if no pattern)
//                webflag - is this a web password?
// Outputs      : 0 if successful test, -1 if failure

func generatePasword(length int8, pattern string, webflag bool) string {

	pwd := "" // Start with nothing and add code
	digits := []string{"0","1","2","3","4","5","6","7","8","9"}
	chars := []string{"a","A","b","B","c","C","d","D","e","E","f","F","g","G","h","H","i","I","j","J","k","K","l","L","m","M","n","N","o","O","p","P","q","Q","r","R","s","S","t","T","u","U","v","V","w","W","x","X","y","Y","z","Z"}
	lowerChars := []string{"a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"}
	upperChars := []string{"A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"}
	specials := []string{"~","!","@","#","$","%","^","&","*","(",")","-","_","=","+","{","}","[","]",":",";","/","?","<",">",",",".","|"} // "\" not included right now

	switch pattern {
	// If no pattern is given, then each character should include a uniformly random single upper or lower case character with Pr(0.33),
	// digit with Pr(0.33), or a special character with Pr(0.33) (as specified in the program help).
	case "":
		var pr int

		switch webflag {
		case true:
			pr = 2
		case false:
			pr = 3
		default:
			fmt.Printf("Error reading webflag\n")
			os.Exit(-1)
		}

		for i := 0; i < int(length); i++ {
			switch rand.Intn(pr) {
			case 0: // Append random digit to password
				pwd = pwd + digits[rand.Intn(len(digits))]
			case 1: // Append random char to password
				pwd = pwd + chars[rand.Intn(len(chars))]
			case 2: // Append random special char to password
				pwd = pwd + specials[rand.Intn(len(specials))]
			default: // Cases above are guaranteed; exit if they somehow don't happen
			fmt.Printf("Error creating password without pattern\n")
				os.Exit(-1)
			}
		}
	// If a pattern is given, the length should be ignored.
	default:
		for i := 0; i < len(pattern); i++ {
			switch string(pattern[i]) {
			case "d": // Append random digit to password
				pwd = pwd + digits[rand.Intn(len(digits))]
			case "c": // Append random char to password
				pwd = pwd + chars[rand.Intn(len(chars))]
			case "l": // Append random lowercase char to password
				pwd = pwd + lowerChars[rand.Intn(len(lowerChars))]
			case "u": // Append random uppercase char to password
				pwd = pwd + upperChars[rand.Intn(len(upperChars))]
			case "w":
				r := regexp.MustCompile("^[0-9]+$").MatchString
				reqLenStart := i + 1
				reqLenEnd := -1
				j := i + 1
				for j < len(pattern) {
					if r(string(pattern[j])) {
						reqLenEnd = j
						j = j + 1
						i = i + 1
					} else {
						break
					}
				}
				if reqLenEnd == -1 {
					pwd = pwd + getDicWord(-1)
				} else {
					fmt.Printf("Start: %d End: %d For %s\n", reqLenStart, reqLenEnd, string(pattern[reqLenStart:reqLenEnd + 1]))
					if reqLen, err := strconv.Atoi(string(pattern[reqLenStart:reqLenEnd + 1])); err != nil {
						fmt.Printf("Could not cast length of word as int\n")
						fmt.Fprintln(os.Stderr, err)
						os.Exit(-1)
					} else {
						pwd = pwd + getDicWord(reqLen)
					}
				}
			case "s": // Append random special char to password
				pwd = pwd + specials[rand.Intn(len(specials))]
			default: // Cases above are guaranteed; exit if they somehow don't happen
				fmt.Printf("Unknown character found in pattern\n")
				os.Exit(-1)
			}
		}
		if len(pwd) >= 65 {
			fmt.Printf("Pattern too long.  The maximum length of a password is 64 characters.\n")
			os.Exit(-1)
		}
	}

	// Now return the password
	return pwd
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the password generator program
//
// Inputs       : none
// Outputs      : 0 if successful test, -1 if failure

var helpflag = getopt.Bool('h', "", "help (this menu)")
var webflag = getopt.Bool('w', "", "web flag (no symbol characters, e.g., no &*...)")
var length = getopt.String('l', "", "length of password (in characters)")
var rng = getopt.Bool('r', "", "use /dev/urandom as seed for RNG")
var pattern = getopt.String('p', "", patternval)

func main() {
	// Now parse the command line arguments
	err := getopt.Getopt(nil)
	if err != nil {
		// Handle error
		fmt.Fprintln(os.Stderr, err)
		getopt.Usage()
		os.Exit(-1)
	}

	/*
	// Get the flags
	fmt.Printf("helpflag [%t]\n", *helpflag)
	fmt.Printf("webflag [%t]\n", *webflag)
	fmt.Printf("length [%s]\n", *length)
	fmt.Printf("seed [%s]\n", *seed)
	fmt.Printf("pattern [%s]\n", *pattern)
	// Normally, we we use getopt.Arg{#) to get the non-flag paramters
	*/

	if *helpflag == true {
		getopt.Usage()
		os.Exit(-1)
	}

	// Setup options for the program content
	switch *rng {
	case true:
		rand.Seed(myOwnRNG())
	default:
		rand.Seed(time.Now().UTC().UnixNano())
	}

	// Safety check length parameter
	// If no length is given, 16 characters should be assumed
	var plength int8 = 16
	if *length != "" {
		if mylen, err := strconv.Atoi(*length); err != nil {
			fmt.Printf("Bad length passed in [%s]\n", *length)
			fmt.Fprintln(os.Stderr, err)
			getopt.Usage()
			os.Exit(-1)
		} else {
			// if no error, get the length from the user
			plength = int8(mylen)
		}
		if plength <= 0 || plength > 64 {
			// The maximum length of a password is 64 characters.
			plength = 16
		}
	}

	// Now generate the password and print it out
	pwd := generatePasword(plength, *pattern, *webflag)
	fmt.Printf("Generated password:  %s\n", pwd)

	// Return (no return code)
	return
}
