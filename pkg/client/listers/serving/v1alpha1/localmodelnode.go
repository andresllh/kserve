/*
Copyright 2023 The KServe Authors.

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

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/kserve/kserve/pkg/apis/serving/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// LocalModelNodeLister helps list LocalModelNodes.
// All objects returned here must be treated as read-only.
type LocalModelNodeLister interface {
	// List lists all LocalModelNodes in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.LocalModelNode, err error)
	// LocalModelNodes returns an object that can list and get LocalModelNodes.
	LocalModelNodes(namespace string) LocalModelNodeNamespaceLister
	LocalModelNodeListerExpansion
}

// localModelNodeLister implements the LocalModelNodeLister interface.
type localModelNodeLister struct {
	indexer cache.Indexer
}

// NewLocalModelNodeLister returns a new LocalModelNodeLister.
func NewLocalModelNodeLister(indexer cache.Indexer) LocalModelNodeLister {
	return &localModelNodeLister{indexer: indexer}
}

// List lists all LocalModelNodes in the indexer.
func (s *localModelNodeLister) List(selector labels.Selector) (ret []*v1alpha1.LocalModelNode, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.LocalModelNode))
	})
	return ret, err
}

// LocalModelNodes returns an object that can list and get LocalModelNodes.
func (s *localModelNodeLister) LocalModelNodes(namespace string) LocalModelNodeNamespaceLister {
	return localModelNodeNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// LocalModelNodeNamespaceLister helps list and get LocalModelNodes.
// All objects returned here must be treated as read-only.
type LocalModelNodeNamespaceLister interface {
	// List lists all LocalModelNodes in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.LocalModelNode, err error)
	// Get retrieves the LocalModelNode from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.LocalModelNode, error)
	LocalModelNodeNamespaceListerExpansion
}

// localModelNodeNamespaceLister implements the LocalModelNodeNamespaceLister
// interface.
type localModelNodeNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all LocalModelNodes in the indexer for a given namespace.
func (s localModelNodeNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.LocalModelNode, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.LocalModelNode))
	})
	return ret, err
}

// Get retrieves the LocalModelNode from the indexer for a given namespace and name.
func (s localModelNodeNamespaceLister) Get(name string) (*v1alpha1.LocalModelNode, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("localmodelnode"), name)
	}
	return obj.(*v1alpha1.LocalModelNode), nil
}
