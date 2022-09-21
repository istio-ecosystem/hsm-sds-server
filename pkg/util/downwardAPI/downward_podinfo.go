package downward

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/constants"
)

func ReadPodLabels() (map[string]string, error) {
	b, err := os.ReadFile(constants.PodInfoLabelsPath)
	if err != nil {
		return nil, err
	}
	return parseDownwardAPI(string(b))
}

func ReadPodAnnotations(path string) (map[string]string, error) {
	if path == "" {
		path = constants.PodInfoAnnotationsPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseDownwardAPI(string(b))
}

// parseDownwardAPI parses fields which are stored as format `%s=%q` back to a map
func parseDownwardAPI(i string) (map[string]string, error) {
	res := map[string]string{}
	for _, line := range strings.Split(i, "\n") {
		sl := strings.SplitN(line, "=", 2)
		if len(sl) != 2 {
			continue
		}
		key := sl[0]
		// Strip the leading/trailing quotes
		val, err := strconv.Unquote(sl[1])
		if err != nil {
			return nil, fmt.Errorf("failed to unquote %v: %v", sl[1], err)
		}
		res[key] = val
	}
	return res, nil
}

