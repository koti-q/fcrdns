package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type ip struct {
	Ip    string
	Count int
}

var resolver = net.Resolver{}

const numWorkers = 100

func main() {

	start := time.Now()
	duration := time.Since(start)

	ips := getIPs()

	jobs := make(chan string, len(ips))
	results := make(chan string, len(ips))

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}

	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)

	wg.Wait()

	// Print results
	for result := range results {
		fmt.Println(result)
	}
	fmt.Println(duration)
}

func worker(jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for ip := range jobs {
		result := isValidPTR(ip)

		results <- result
	}
}

func getIPs() []string {
	if len(os.Args) >= 2 {
		return os.Args[1:]
	} else {
		f, _ := os.ReadFile("./banned-ips.txt")
		return strings.Split(string(f), "\n")
	}
}

func isValidPTR(ip string) string {

	domains, err := resolver.LookupAddr(context.Background(), ip)

	if err != nil {
		return fmt.Sprintf("---PTR request error for %s - %v", ip, err)
	}

	for _, domain := range domains {
		names, err := net.LookupHost(domain)

		if err != nil {
			return fmt.Sprintf("%s - Not forward-confirmed DNS lookup", domain)
		}

		if len(names) > 0 {
			for name := range names {
				if names[name] == ip {
					return fmt.Sprintf("%s - forward-confirmed", domain)
				}
			}

		}
	}
	return ""
}
