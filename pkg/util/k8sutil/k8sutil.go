/*
Copyright 2021 Intel Coporation.
SPDX-License-Identifier: Apache-2.0
*/

package k8sutil

import (
	"strings"

	"github.com/intel-innersource/applications.services.cloud.hsm-sds-server/pkg/constants"
)

type SignerIssuerRef struct {
	Namespace, Name string
	Type, Group     string
}

// SignerIssuerRefFromSignerName will return a SignerIssuerRef from a
// CertificateSigningRequests.Spec.SignerName
func SignerIssuerRefFromSignerName(name string) (SignerIssuerRef, bool) {
	split := strings.Split(name, "/")
	if len(split) != 2 {
		return SignerIssuerRef{}, false
	}

	signerTypeSplit := strings.SplitN(split[0], ".", 2)
	signerNameSplit := strings.Split(split[1], ".")

	if len(signerTypeSplit) < 2 || signerNameSplit[0] == "" {
		return SignerIssuerRef{}, false
	}

	if len(signerNameSplit) == 1 {
		return SignerIssuerRef{
			Namespace: "",
			Name:      signerNameSplit[0],
			Type:      signerTypeSplit[0],
			Group:     signerTypeSplit[1],
		}, true
	}

	// ClusterIssuers do not have Namespaces
	if signerTypeSplit[0] == "clusterissuers" {
		return SignerIssuerRef{
			Namespace: "",
			Name:      strings.Join(signerNameSplit[0:], "."),
			Type:      signerTypeSplit[0],
			Group:     signerTypeSplit[1],
		}, true
	}

	// Non Cluster Scoped issuers always have Namespaces
	return SignerIssuerRef{
		Namespace: signerNameSplit[0],
		Name:      strings.Join(signerNameSplit[1:], "."),
		Type:      signerTypeSplit[0],
		Group:     signerTypeSplit[1],
	}, true
}

// IssuerKindFromType will return the cert-manager.io Issuer Kind from a
// resource type name.
func IssuerKindFromType(issuerType string) (string, bool) {
	switch issuerType {
	case "issuers":
		return constants.IssuerKind, true

	case "clusterissuers":
		return constants.ClusterIssuerKind, true

	default:
		return "", false
	}
}
