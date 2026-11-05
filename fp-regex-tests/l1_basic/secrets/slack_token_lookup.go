package main
import ("fmt"; "os")

var slackToken = os.Getenv("SLACK_TOKEN")
func main() { fmt.Println(slackToken) }
