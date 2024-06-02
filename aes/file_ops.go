package aes

import (
	"bufio"
	"io"
	"os"
	"os/exec"
)

const (
	ChunckSize = 1024 * 1024
)

func EncryptFile(cipher *Cipher, infile, outfile string) error {
	in, err := os.OpenFile(infile, os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	handle := bufio.NewReader(in)
	readBuf := make([]byte, ChunckSize)
	for {
		bytesRead, err := handle.Read(readBuf)
		if err != nil && err != io.EOF {
			return err
		}
		if bytesRead == 0 && err == io.EOF {
			return nil
		}
		c, err := cipher.Encrypt(readBuf[:bytesRead])
		if err != nil {
			return err
		}
		if _, e := out.Write(c); e != nil {
			return e
		}
		bzero(readBuf[:bytesRead])
	}
}

func DecryptFile(cipher *Cipher, infile, outfile string) error {
	in, err := os.OpenFile(infile, os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	handle := bufio.NewReader(in)
	readBuf := make([]byte, ChunckSize)
	for {
		bytesRead, err := handle.Read(readBuf)
		if err != nil && err != io.EOF {
			return err
		}
		if bytesRead == 0 && err == io.EOF {
			return nil
		}
		c, err := cipher.Decrypt(readBuf[:bytesRead])
		if err != nil {
			return err
		}
		if _, e := out.Write(c); e != nil {
			return e
		}
		bzero(readBuf[:bytesRead])
	}
}

func bzero(slice []byte) {
	for i := range slice {
		slice[i] = 0
	}
}

func CompareFiles(file1, file2 string) (string, bool, error) {
	cmd := exec.Command("diff", "-a", file1, file2)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitStatus, ok := err.(*exec.ExitError); ok {
			if exitStatus.ExitCode() == 1 {
				return string(output), false, nil
			}
		}
		return "", false, err
	}
	return string(output), true, nil
}

func RemoveFiles(files ...string) {
	for _, file := range files {
		if err := os.Remove(file); err != nil {
			panic(err)
		}
	}
}
