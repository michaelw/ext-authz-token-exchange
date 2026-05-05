package policy

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
)

// Store provides the current immutable policy index.
type Store interface {
	Index() *Index
}

// StaticStore is a Store backed by a fixed index, primarily for tests.
type StaticStore struct {
	index *Index
}

// NewStaticStore returns a Store backed by index.
func NewStaticStore(index *Index) StaticStore {
	if index == nil {
		index = EmptyIndex()
	}
	return StaticStore{index: index}
}

// Index returns the fixed policy index.
func (s StaticStore) Index() *Index {
	return s.index
}

// ConfigMapStore watches app-owned ConfigMaps and rebuilds the policy index.
type ConfigMapStore struct {
	cfg               config.RuntimeConfig
	client            kubernetes.Interface
	namespaceSelector labels.Selector
	index             atomic.Value
	mu                sync.Mutex
	configs           map[Source]string
	selected          map[string]struct{}
	namespaceCancels  map[string]context.CancelFunc
}

// NewConfigMapStore builds a ConfigMapStore from an in-cluster Kubernetes client.
func NewConfigMapStore(cfg config.RuntimeConfig) (*ConfigMapStore, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}
	return NewConfigMapStoreWithClient(client, cfg), nil
}

// NewConfigMapStoreWithClient builds a ConfigMapStore with the supplied client.
func NewConfigMapStoreWithClient(client kubernetes.Interface, cfg config.RuntimeConfig) *ConfigMapStore {
	namespaceSelector, err := labels.Parse(cfg.NamespaceSelector)
	if err != nil {
		namespaceSelector = labels.Nothing()
	}
	store := &ConfigMapStore{
		cfg:               cfg,
		client:            client,
		namespaceSelector: namespaceSelector,
		configs:           make(map[Source]string),
		selected:          make(map[string]struct{}),
		namespaceCancels:  make(map[string]context.CancelFunc),
	}
	store.index.Store(EmptyIndex())
	return store
}

// Index returns the latest immutable policy snapshot.
func (s *ConfigMapStore) Index() *Index {
	value := s.index.Load()
	if value == nil {
		return EmptyIndex()
	}
	return value.(*Index)
}

// Run starts namespace-scoped ConfigMap watch loops and blocks until ctx is canceled.
func (s *ConfigMapStore) Run(ctx context.Context) error {
	namespaces := s.client.CoreV1().Namespaces()
	initial, err := namespaces.List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for i := range initial.Items {
		ns := initial.Items[i]
		if !s.namespaceMatches(&ns) {
			continue
		}
		if err := s.addNamespace(ctx, ns.Name); err != nil {
			return err
		}
	}

	listWatch := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return namespaces.List(ctx, options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return namespaces.Watch(ctx, options)
		},
	}

	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: listWatch,
		ObjectType:    &corev1.Namespace{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				s.upsertNamespace(ctx, obj)
			},
			UpdateFunc: func(_, newObj any) {
				s.upsertNamespace(ctx, newObj)
			},
			DeleteFunc: func(obj any) {
				s.deleteNamespace(obj)
			},
		},
		ResyncPeriod: 10 * time.Minute,
	})

	go controller.Run(ctx.Done())
	<-ctx.Done()
	return nil
}

func (s *ConfigMapStore) addNamespace(ctx context.Context, namespace string) error {
	s.mu.Lock()
	if _, ok := s.selected[namespace]; ok {
		s.mu.Unlock()
		return nil
	}
	nsCtx, cancel := context.WithCancel(ctx)
	s.selected[namespace] = struct{}{}
	s.namespaceCancels[namespace] = cancel
	s.mu.Unlock()

	configMaps := s.client.CoreV1().ConfigMaps(namespace)
	initial, err := configMaps.List(ctx, metav1.ListOptions{LabelSelector: s.cfg.LabelSelector})
	if err != nil {
		cancel()
		s.removeNamespace(namespace)
		return err
	}
	for i := range initial.Items {
		cm := initial.Items[i]
		s.upsert(&cm)
	}

	listWatch := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.LabelSelector = s.cfg.LabelSelector
			return configMaps.List(nsCtx, options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.LabelSelector = s.cfg.LabelSelector
			return configMaps.Watch(nsCtx, options)
		},
	}
	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: listWatch,
		ObjectType:    &corev1.ConfigMap{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				s.upsert(obj)
			},
			UpdateFunc: func(_, newObj any) {
				s.upsert(newObj)
			},
			DeleteFunc: func(obj any) {
				s.delete(obj)
			},
		},
		ResyncPeriod: 10 * time.Minute,
	})
	go controller.Run(nsCtx.Done())
	return nil
}

func (s *ConfigMapStore) upsertNamespace(ctx context.Context, obj any) {
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		return
	}
	if !s.namespaceMatches(ns) {
		s.removeNamespace(ns.Name)
		return
	}
	if err := s.addNamespace(ctx, ns.Name); err != nil {
		log.Printf("failed to watch policy ConfigMaps in namespace %s: %v", ns.Name, err)
	}
}

func (s *ConfigMapStore) namespaceMatches(ns *corev1.Namespace) bool {
	return s.namespaceSelector.Matches(labels.Set(ns.Labels))
}

func (s *ConfigMapStore) deleteNamespace(obj any) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		return
	}
	s.removeNamespace(ns.Name)
}

func (s *ConfigMapStore) removeNamespace(namespace string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancel, ok := s.namespaceCancels[namespace]; ok {
		cancel()
		delete(s.namespaceCancels, namespace)
	}
	delete(s.selected, namespace)
	for source := range s.configs {
		if source.Namespace == namespace {
			delete(s.configs, source)
		}
	}
	s.rebuildLocked()
}

func (s *ConfigMapStore) upsert(obj any) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return
	}
	data, ok := cm.Data["config.yaml"]
	source := Source{Namespace: cm.Namespace, Name: cm.Name}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, selected := s.selected[cm.Namespace]; !selected {
		return
	}
	if ok {
		s.configs[source] = data
	} else {
		log.Printf("policy ConfigMap %s/%s missing data[config.yaml]; marking as invalid", cm.Namespace, cm.Name)
		s.configs[source] = ""
	}
	s.rebuildLocked()
}

func (s *ConfigMapStore) delete(obj any) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, selected := s.selected[cm.Namespace]; !selected {
		return
	}
	delete(s.configs, Source{Namespace: cm.Namespace, Name: cm.Name})
	s.rebuildLocked()
}

func (s *ConfigMapStore) rebuildLocked() {
	copied := make(map[Source]string, len(s.configs))
	for source, data := range s.configs {
		copied[source] = data
	}
	s.index.Store(BuildIndex(copied, s.cfg))
}
