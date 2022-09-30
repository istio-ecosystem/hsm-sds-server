/*
Copyright 2021 Intel(R)
SPDX-License-Identifier: Apache-2.0
*/

package cmutil

import (
	"math/rand"
	"strconv"
	"strings"
	"time"
)

func GenerateSecretName(signerName string) string {
	if strings.Contains(signerName, "/") {
		signerName = strings.Replace(signerName, "/", "-", -1)
	}
	if strings.Contains(signerName, ".") {
		signerName = strings.Replace(signerName, ".", "-", -1)
	}
	rs := rand.NewSource(time.Now().UnixNano())
	r := rand.New(rs)
	return signerName + "-" + strconv.Itoa(int(r.Int31()))
}
