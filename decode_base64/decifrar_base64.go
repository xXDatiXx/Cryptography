package main

import (
	"encoding/base64" //Esta librería es la que nos ayuda a decodificar el texto en base64
	"fmt"
	"log"
)

func decifrarBase64(cipherTextBase64 string) string {
	// Decodificar Base64
	data, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		log.Fatal("Error decodificando Base64:", err)
	}
	return string(data)
}

func main() {
	// Texto codificado en Base64
	cipherTextBase64_1 := `
UFJWIFhLIFZGVVNMQlFRSCBBSEkgSVJIRFIgUEhaVUJXTC4gwqFZQldCIEdCIEROWEYs
IEZPTFhXUlVYIEdCIElSSERSISDCoUtSIE1EUERPRFAh
`
	// Clave codificada en Base64
	cipherTextBase64_2 := "eEQ="

	// Decodificar Base64 e imprimir texto decifrado
	fmt.Println("Texto decifrado:", decifrarBase64(cipherTextBase64_1))
	fmt.Println("Clave:", decifrarBase64(cipherTextBase64_2))
}
