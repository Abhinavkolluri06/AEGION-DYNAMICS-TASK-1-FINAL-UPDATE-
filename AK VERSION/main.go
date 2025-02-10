package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type licensefile struct {
	expiry_date string
	user_id     string
}

var Encryptedfile string = "Encryptedfile.txt"

func (eg *licensefile) read_info(date *string, user_id *string) {
	fmt.Println("Enter the expiry date of the license file in YYYY-MM-DD format:")
	fmt.Scanln(&eg.expiry_date)
	*date = eg.expiry_date
	fmt.Println("Enter the User Id:")
	fmt.Scanln(&eg.user_id)
	*user_id = eg.user_id
}

func (eg *licensefile) open_file(filename string) {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("Error in opening the file:", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString("expiry_date:" + eg.expiry_date + "\n")
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	_, err = file.WriteString("User_id:" + eg.user_id + "\n")
	if err != nil {
		fmt.Println("Error writing to file:", err)
	}
}

func encryptfile(inputfile string, outputfile string, Sprivatekey *rsa.PrivateKey) error {
	file, err := os.Open(inputfile)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer file.Close()

	plaintext, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &Sprivatekey.PublicKey, plaintext, nil)
	if err != nil {
		return fmt.Errorf("error encrypting data: %w", err)
	}

	encryptedfile, err := os.Create(outputfile)
	if err != nil {
		return fmt.Errorf("error creating encrypted file: %w", err)
	}
	defer encryptedfile.Close()

	_, err = encryptedfile.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("error writing encrypted data: %w", err)
	}

	return nil
}

func decryptfile(encryptedfile, outputfile string, Sprivatekey *rsa.PrivateKey) error {
	file, err := os.Open(encryptedfile)
	if err != nil {
		return fmt.Errorf("error opening encrypted file: %w", err)
	}
	defer file.Close()

	ciphertext, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("error reading encrypted file: %w", err)
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, Sprivatekey, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("error decrypting data: %w", err)
	}

	decryptedfile, err := os.Create(outputfile)
	if err != nil {
		return fmt.Errorf("error creating decrypted file: %w", err)
	}
	defer decryptedfile.Close()

	_, err = decryptedfile.Write(plaintext)
	if err != nil {
		return fmt.Errorf("error writing decrypted data: %w", err)
	}

	return nil
}

func GeneratePrivatekeyFile() *rsa.PrivateKey {
	Sprivatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error in generating private key")
		return nil
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(Sprivatekey)
	encodedKey := base64.StdEncoding.EncodeToString(privateKeyBytes)
	fmt.Println("Generated Private Key (Base64 Encoded):", encodedKey)

	return Sprivatekey
}

func DecodePrivateKey(encodedKey string) (*rsa.PrivateKey, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedKey))
	if err != nil {
		return nil, fmt.Errorf("error decoding private key: %w", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(decodedBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}

	return privateKey, nil
}

func validateLicense(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("error opening the file: %w", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return false, fmt.Errorf("error reading the file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "expiry_date:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "expiry_date:"))
			expiryDate, err := time.Parse("2006-01-02", dateStr)
			if err != nil {
				return false, fmt.Errorf("invalid date format in the file: %w", err)
			}

			if time.Now().Before(expiryDate) {
				return true, nil
			}
			return false, nil
		}
	}
	return false, fmt.Errorf("expiry_date not found in the file")
}

func displaycontentinfile(filename string) error {

	file, err := os.Open(filename)
	if err != nil {

		return fmt.Errorf("error in opening the file : %w", err)

	}

	content, err := io.ReadAll(file)
	if err != nil {

		return fmt.Errorf("error in reading the file : %w", err)

	}

	fmt.Println("Input given by user :")

	fmt.Println(string(content))
	return nil
}

//checing if the License file exists or no

func checkFileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}

func main() {
	lcfile := licensefile{}
	var temp1, temp2 string
	lcfile.read_info(&temp1, &temp2)
	fmt.Printf("The expiry date of the license file is %s \n", temp1)

	var filename string
	fmt.Println("Enter the filename with type:")
	fmt.Scanln(&filename)
	lcfile.open_file(filename)

	prkey := GeneratePrivatekeyFile()
	if prkey == nil {
		return
	}

	err := encryptfile(filename, "Encryptedfile.txt", prkey)
	if err != nil {
		fmt.Println("Error in encrypting the file:", err)
		return
	}
	fmt.Println("File encrypted successfully")

	var condi string
	fmt.Println("Do you want to decrypt the file (Y/N):")
	fmt.Scanln(&condi)

	if strings.ToUpper(condi) == "Y" {
		fmt.Println("Enter the private key:")
		reader := bufio.NewReader(os.Stdin)
		encodedKey, _ := reader.ReadString('\n')

		inputKey, err := DecodePrivateKey(encodedKey)
		if err != nil {
			fmt.Println("Error loading private key:", err)
			return
		}

		err = decryptfile(Encryptedfile, "decryptedfile.txt", inputKey)
		if err != nil {
			fmt.Println("Error in decrypting the file:", err)
			return
		}

		fmt.Println("File decrypted successfully")

		valid, err := validateLicense(filename)
		if err != nil {
			fmt.Println("Error validating the license:", err)
			return
		}

		if valid {
			fmt.Println("------------------------------------------")
			fmt.Println(" License is valid. Access granted.\n", "displaying the contents inside the file:")
			fmt.Println("-----------------------------------------")
			err := displaycontentinfile(filename)
			if err != nil {
				fmt.Println("error while displaying the file : %w", err)
			}
		} else {
			fmt.Println("License has expired. Access denied !!! .")
		}

		// file checking for every 24 hours
		if checkFileExists(filename) {
			fmt.Println("File exists.")
		} else {

			fmt.Println("File does not exist.")
		}

		time.Sleep(10 * time.Second)

	} else {
		fmt.Println("File decryption stopped")
	}

}
