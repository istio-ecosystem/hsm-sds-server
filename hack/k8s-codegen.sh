#!/usr/bin/env bash

# Copyright The Istio Authors.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

go=$1

clientgen=$2
deepcopygen=$3
informergen=$4
listergen=$5

# If the envvar "VERIFY_ONLY" is set, we only check if everything's up to date
# and don't actually generate anything

VERIFY_FLAGS=""
VERB="Generating"

if [[ ${VERIFY_ONLY:-} ]]; then
	VERIFY_FLAGS="--verify-only"
	VERB="Verifying"
fi

export VERIFY_FLAGS
export VERB

echo "+++ ${VERB} code..." >&2

module_name="github.com/intel-innersource/applications.services.cloud.hsm-sds-server"

# Generate deepcopy functions for all internal and external APIs
deepcopy_inputs=(
  pkg/apis/tcs/v1alpha1 \
)

client_subpackage="pkg/client"
client_package="${module_name}/${client_subpackage}"
# Generate clientsets, listers and informers for user-facing API types
client_inputs=(
  pkg/apis/tcs/v1alpha1 \
)

# clean will delete files matching name in path.
clean() {
  if [[ ${VERIFY_ONLY:-} ]]; then
      # don't delete files if we're only verifying
      return 0
  fi

  path=$1
  name=$2
  if [[ ! -d "$path" ]]; then
    return 0
  fi
  find "$path" -name "$name" -delete
}

mkcp() {
  src="$1"
  dst="$2"
  mkdir -p "$(dirname "$dst")"
  cp "$src" "$dst"
}

# Export mkcp for use in sub-shells
export -f mkcp

gen-deepcopy() {
  clean pkg/apis 'zz_generated.deepcopy.go'
  echo "+++ ${VERB} deepcopy methods..." >&2
  prefixed_inputs=( "${deepcopy_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$deepcopygen" \
    ${VERIFY_FLAGS} \
    --go-header-file hack/boilerplate/boilerplate.generatego.txt \
    --input-dirs "$joined" \
    --output-file-base zz_generated.deepcopy \
    --trim-path-prefix="$module_name" \
    --bounding-dirs "${module_name}" \
    --output-base ./
}

gen-clientsets() {
  clean "${client_subpackage}"/clientset '*.go'
  echo "+++ ${VERB} clientset..." >&2
  prefixed_inputs=( "${client_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$clientgen" \
    ${VERIFY_FLAGS} \
    --go-header-file hack/boilerplate/boilerplate.generatego.txt \
    --clientset-name versioned \
    --input-base "" \
    --input "$joined" \
    --trim-path-prefix="$module_name" \
    --output-package "${client_package}"/clientset \
    --output-base ./
}

gen-listers() {
  clean "${client_subpackage}/listers" '*.go'
  echo "+++ ${VERB} listers..." >&2
  prefixed_inputs=( "${client_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$listergen" \
    ${VERIFY_FLAGS} \
    --go-header-file hack/boilerplate/boilerplate.generatego.txt \
    --input-dirs "$joined" \
    --trim-path-prefix="$module_name" \
    --output-package "${client_package}"/listers \
    --output-base ./
}

gen-informers() {
  clean "${client_subpackage}"/informers '*.go'
  echo "+++ ${VERB} informers..." >&2
  prefixed_inputs=( "${client_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$informergen" \
    ${VERIFY_FLAGS} \
    --go-header-file hack/boilerplate/boilerplate.generatego.txt \
    --input-dirs "$joined" \
    --versioned-clientset-package "${client_package}"/clientset/versioned \
    --listers-package "${client_package}"/listers \
    --trim-path-prefix="$module_name" \
    --output-package "${client_package}"/informers \
    --output-base ./
}

gen-deepcopy
gen-clientsets
gen-listers
gen-informers
