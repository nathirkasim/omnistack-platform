package main
import "crypto/tls"

func createConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}
func main() {}
