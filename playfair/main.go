package main

import (
	"fmt"
	"strings"
)

// getPosition obtiene la posición de un carácter en el key_square
func getPosition(char rune, square [5][5]rune) (int, int) {
	for i, row := range square {
		for j, val := range row {
			if val == char {
				return i, j
			}
		}
	}
	return -1, -1
}

// playfairDecrypt descifra el texto cifrado usando el cifrado Playfair
func playfairDecrypt(ciphertext string, keySquare [5][5]rune) string {
	var decryptedText strings.Builder
	i := 0

	for i < len(ciphertext) {
		a := rune(ciphertext[i])
		b := rune(ciphertext[i+1])

		rowA, colA := getPosition(a, keySquare)
		rowB, colB := getPosition(b, keySquare)

		// Mismo fila
		if rowA == rowB {
			decryptedText.WriteRune(keySquare[rowA][(colA+4)%5])
			decryptedText.WriteRune(keySquare[rowB][(colB+4)%5])
		} else if colA == colB { // Misma columna
			decryptedText.WriteRune(keySquare[(rowA+4)%5][colA])
			decryptedText.WriteRune(keySquare[(rowB+4)%5][colB])
		} else { // Rectángulo
			decryptedText.WriteRune(keySquare[rowA][colB])
			decryptedText.WriteRune(keySquare[rowB][colA])
		}

		i += 2
	}

	return decryptedText.String()
}

func main() {
	keySquare := [5][5]rune{
		{'X', 'H', 'O', 'L', 'I'},
		{'C', 'A', 'B', 'D', 'E'},
		{'F', 'G', 'K', 'M', 'N'},
		{'P', 'Q', 'R', 'S', 'T'},
		{'U', 'V', 'W', 'Y', 'Z'},
	}

	ciphertext := "difymexrzcectdskvztcpvbitlilixnlqeqdilpvnzzctzenmedtxrntwlwpdzdt"

	decryptedText := playfairDecrypt(strings.ToUpper(ciphertext), keySquare)
	fmt.Println(strings.ToLower(decryptedText))
}
