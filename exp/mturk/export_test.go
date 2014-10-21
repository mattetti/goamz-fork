package mturk

import (
	"github.com/mattetti/goamz-fork/aws"
)

func Sign(auth aws.Auth, service, method, timestamp string, params map[string]string) {
	sign(auth, service, method, timestamp, params)
}
