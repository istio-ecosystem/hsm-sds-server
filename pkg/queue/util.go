// COPY from Istio source code
package queue

import (
	"fmt"
	"time"
)

// WaitForClose blocks until the Instance has stopped processing tasks or the timeout expires.
// If the timeout is zero, it will wait until the queue is done processing.
// WaitForClose an error if the timeout expires.
func WaitForClose(q Instance, timeout time.Duration) error {
	closed := q.Closed()
	if timeout == 0 {
		<-closed
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-closed:
		return nil
	case <-timer.C:
		return fmt.Errorf("timeout waiting for queue to close after %v", timeout)
	}
}
