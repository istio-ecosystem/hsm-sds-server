/*
Copyright The Istio Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha2 "istio-ecosystem/hsm-sds-server/pkg/apis/tcs/v1alpha2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeQuoteAttestations implements QuoteAttestationInterface
type FakeQuoteAttestations struct {
	Fake *FakeTcsV1alpha2
	ns   string
}

var quoteattestationsResource = schema.GroupVersionResource{Group: "tcs.intel.com", Version: "v1alpha2", Resource: "quoteattestations"}

var quoteattestationsKind = schema.GroupVersionKind{Group: "tcs.intel.com", Version: "v1alpha2", Kind: "QuoteAttestation"}

// Get takes name of the quoteAttestation, and returns the corresponding quoteAttestation object, and an error if there is any.
func (c *FakeQuoteAttestations) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha2.QuoteAttestation, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(quoteattestationsResource, c.ns, name), &v1alpha2.QuoteAttestation{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha2.QuoteAttestation), err
}

// List takes label and field selectors, and returns the list of QuoteAttestations that match those selectors.
func (c *FakeQuoteAttestations) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha2.QuoteAttestationList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(quoteattestationsResource, quoteattestationsKind, c.ns, opts), &v1alpha2.QuoteAttestationList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha2.QuoteAttestationList{ListMeta: obj.(*v1alpha2.QuoteAttestationList).ListMeta}
	for _, item := range obj.(*v1alpha2.QuoteAttestationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested quoteAttestations.
func (c *FakeQuoteAttestations) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(quoteattestationsResource, c.ns, opts))

}

// Create takes the representation of a quoteAttestation and creates it.  Returns the server's representation of the quoteAttestation, and an error, if there is any.
func (c *FakeQuoteAttestations) Create(ctx context.Context, quoteAttestation *v1alpha2.QuoteAttestation, opts v1.CreateOptions) (result *v1alpha2.QuoteAttestation, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(quoteattestationsResource, c.ns, quoteAttestation), &v1alpha2.QuoteAttestation{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha2.QuoteAttestation), err
}

// Update takes the representation of a quoteAttestation and updates it. Returns the server's representation of the quoteAttestation, and an error, if there is any.
func (c *FakeQuoteAttestations) Update(ctx context.Context, quoteAttestation *v1alpha2.QuoteAttestation, opts v1.UpdateOptions) (result *v1alpha2.QuoteAttestation, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(quoteattestationsResource, c.ns, quoteAttestation), &v1alpha2.QuoteAttestation{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha2.QuoteAttestation), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeQuoteAttestations) UpdateStatus(ctx context.Context, quoteAttestation *v1alpha2.QuoteAttestation, opts v1.UpdateOptions) (*v1alpha2.QuoteAttestation, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(quoteattestationsResource, "status", c.ns, quoteAttestation), &v1alpha2.QuoteAttestation{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha2.QuoteAttestation), err
}

// Delete takes name of the quoteAttestation and deletes it. Returns an error if one occurs.
func (c *FakeQuoteAttestations) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(quoteattestationsResource, c.ns, name, opts), &v1alpha2.QuoteAttestation{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeQuoteAttestations) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(quoteattestationsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha2.QuoteAttestationList{})
	return err
}

// Patch applies the patch and returns the patched quoteAttestation.
func (c *FakeQuoteAttestations) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha2.QuoteAttestation, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(quoteattestationsResource, c.ns, name, pt, data, subresources...), &v1alpha2.QuoteAttestation{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha2.QuoteAttestation), err
}
