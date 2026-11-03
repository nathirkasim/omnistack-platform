package main

import (
	"fmt"
	"html"
	"html/template"
	"net/http"
	"os/exec"
	"strconv"
)

var (
	orderRepo   = &OrderRepository{}
	orderSvc    = &OrderService{repo: orderRepo}
	statefulSvc = &StatefulTaskService{}
)

func runWorker(ch <-chan string) {
	for cmd := range ch {
		// GT: id=TAINT-GO-002 type=TP cwe=CWE-78 rule=goroutine-channel-exec
		_ = exec.Command("sh", "-c", cmd).Run()
	}
}

func runSafeWorker(ch <-chan string) {
	for val := range ch {
		// GT: id=TAINT-GO-012 type=FP reason=channel-allowlist-validated
		_ = exec.Command("echo", val).Run()
	}
}

func closureExecutor(payload string, fn func(string) []byte) []byte {
	return fn(payload)
}

func main() {
	workerCh := make(chan string, 10)
	safeWorkerCh := make(chan string, 10)
	go runWorker(workerCh)
	go runSafeWorker(safeWorkerCh)

	http.HandleFunc("/advanced/taint/channel/exec", func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		workerCh <- cmd
		fmt.Fprintf(w, "Enqueued")
	})

	http.HandleFunc("/advanced/taint/channel/safe-exec", func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("val")
		if strictAlphaNumeric(val) {
			safeWorkerCh <- val
		}
		fmt.Fprintf(w, "Enqueued safe")
	})

	http.HandleFunc("/advanced/taint/closure/exec", func(w http.ResponseWriter, r *http.Request) {
		payload := r.URL.Query().Get("payload")
		// GT: id=TAINT-GO-004 type=TP cwe=CWE-78 rule=closure-function-pointer-exec
		res := closureExecutor(payload, func(p string) []byte {
			out, _ := exec.Command("sh", "-c", p).Output()
			return out
		})
		w.Write(res)
	})

	http.HandleFunc("/advanced/taint/int-cast/lookup", func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("id")
		// GT: id=TAINT-GO-014 type=FP reason=int-cast-breaks-taint
		idVal, err := strconv.Atoi(raw)
		if err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		fmt.Fprintf(w, "ID: %d", idVal)
	})

	http.HandleFunc("/advanced/taint/framework/raw-html", func(w http.ResponseWriter, r *http.Request) {
		comment := r.URL.Query().Get("comment")
		// GT: id=TAINT-GO-008 type=TP cwe=CWE-79 rule=framework-template-html-bypass
		rendered := template.HTML(comment)
		fmt.Fprintf(w, "<div>%s</div>", rendered)
	})

	http.HandleFunc("/advanced/taint/framework/escaped-html", func(w http.ResponseWriter, r *http.Request) {
		comment := r.URL.Query().Get("comment")
		// GT: id=TAINT-GO-016 type=FP reason=correct-html-escape
		safe := html.EscapeString(comment)
		fmt.Fprintf(w, "<div>%s</div>", safe)
	})

	http.HandleFunc("/advanced/taint/branch/guarded", func(w http.ResponseWriter, r *http.Request) {
		mode := r.URL.Query().Get("mode")
		if mode == "safe" {
			// GT: id=TAINT-GO-015 type=FP reason=sink-on-safe-branch-only
			fmt.Fprintf(w, "safe-constant-response")
			return
		}
		http.Error(w, "denied", 403)
	})

	http.HandleFunc("/advanced/taint/auth/admin-action", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Role") != "SuperAdmin" {
			http.Error(w, "forbidden", 403)
			return
		}
		// GT: id=TAINT-GO-020 type=FP reason=role-based-auth-guard
		fmt.Fprintf(w, "admin-ok")
	})

	_ = http.ListenAndServe(":8081", nil)
}
