package main
import "os/exec"

func runShell(input string) {
	_ = exec.Command("sh", "-c", input).Run()
}
func runDirect(arg string) {
	_ = exec.Command("ls", "-l", arg).Run()
}
func main() {}
