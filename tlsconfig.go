// Copyright (c) 2026 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	sdktls "open-cluster-management.io/sdk-go/pkg/tls"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"open-cluster-management.io/governance-policy-framework-addon/tool"
)

// errInvalidTLSGroups marks an invalid --tls-groups value so the caller exits instead of using defaults.
var errInvalidTLSGroups = errors.New("invalid --tls-groups value")

// resolveEffectiveTLSConfig merges settings by precedence: flags, the ocm-tls-profile ConfigMap,
// the APIServer TLS profile (groups only), then Go's TLS defaults.
func resolveEffectiveTLSConfig(
	ctx context.Context, cfg *rest.Config, minVersion, cipherSuites, groups string,
) (tlsOptsFunc func(*tls.Config), watchAPIServer bool, resolvedSpec configv1.TLSProfileSpec, err error) {
	flagCfg, err := sdktls.ConfigFromFlags(minVersion, cipherSuites)
	if err != nil {
		return nil, false, configv1.TLSProfileSpec{}, err
	}

	var configMapTLS *sdktls.TLSConfig

	if strings.TrimSpace(minVersion) == "" || strings.TrimSpace(cipherSuites) == "" {
		configMapTLS, err = resolveOCMTLSConfigMap(ctx, cfg)
		if err != nil {
			log.Error(err, "Failed to resolve the ocm-tls-profile ConfigMap; using defaults")
		}
	}

	tlsSource := sdktls.GetDefaultTLSConfig()
	if configMapTLS != nil {
		tlsSource = configMapTLS
	}

	if flagCfg != nil {
		if strings.TrimSpace(minVersion) != "" {
			tlsSource.MinVersion = flagCfg.MinVersion
		}

		if strings.TrimSpace(cipherSuites) != "" {
			tlsSource.CipherSuites = flagCfg.CipherSuites
		}
	}

	curves, unsupportedGroups := libgocrypto.TLSGroupsToCurveIDs(splitTLSGroups(groups))

	if len(unsupportedGroups) > 0 {
		return nil, false, configv1.TLSProfileSpec{}, fmt.Errorf("%w: %v", errInvalidTLSGroups, unsupportedGroups)
	}

	if len(curves) == 0 {
		resolvedSpec, watchAPIServer = readAPIServerTLSProfileSpec(ctx, cfg)
		curves, unsupportedGroups = libgocrypto.TLSGroupsToCurveIDs(resolvedSpec.Groups)

		if len(unsupportedGroups) > 0 {
			log.Info("Some TLS groups are not supported and will be ignored", "groups", unsupportedGroups)
		}
	}

	applySourceTLS := sdktls.ConfigToFunc(tlsSource)

	tlsOptsFunc = func(tlsConf *tls.Config) {
		applySourceTLS(tlsConf)

		if len(curves) > 0 {
			tlsConf.CurvePreferences = curves
		}
	}

	log.Info("Resolved TLS configuration",
		"minVersion", sdktls.VersionToString(tlsSource.MinVersion),
		"cipherSuites", sdktls.CipherSuitesToString(tlsSource.CipherSuites),
		"tlsGroups", fmt.Sprint(curves))

	return tlsOptsFunc, watchAPIServer, resolvedSpec, nil
}

func resolveOCMTLSConfigMap(ctx context.Context, cfg *rest.Config) (*sdktls.TLSConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	namespace, err := tool.GetOperatorNamespace()
	if err != nil {
		if errors.Is(err, tool.ErrNoNamespace) || errors.Is(err, tool.ErrRunLocal) {
			log.Info("Not running in a cluster; skipping the ocm-tls-profile ConfigMap watch")
		} else {
			log.Error(err, "Failed to get operator namespace; skipping the ocm-tls-profile ConfigMap watch")
		}

		return nil, nil
	}

	return startTLSConfigMapWatcher(ctx, kubernetes.NewForConfigOrDie(cfg), namespace)
}

// The ConfigMap watcher below needs get/list/watch on the ocm-tls-profile ConfigMap in the
// addon's own namespace. sdktls.StartTLSConfigMapWatcher lists/watches with a metadata.name field
// selector matching ConfigMapName, which is what lets list/watch be scoped by resourceNames here
// (see the secretsync package's identical pattern for policy-encryption-key).
//+kubebuilder:rbac:groups=core,resources=configmaps,resourceNames=ocm-tls-profile,verbs=get;list;watch
//+kubebuilder:rbac:groups=config.openshift.io,resources=apiservers,verbs=get;list;watch

// startTLSConfigMapWatcher returns the ConfigMap TLS config and starts its watcher, erroring if list/watch is denied.
func startTLSConfigMapWatcher(
	ctx context.Context, kubeClient kubernetes.Interface, namespace string,
) (*sdktls.TLSConfig, error) {
	allowed, err := canWatch(ctx, kubeClient, authorizationv1.ResourceAttributes{
		Namespace: namespace,
		Resource:  "configmaps",
		Name:      sdktls.ConfigMapName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to check permission to watch the %s ConfigMap: %w",
			sdktls.ConfigMapName, err)
	}

	if !allowed {
		return nil, fmt.Errorf("missing permission to list/watch the %s ConfigMap in namespace %s",
			sdktls.ConfigMapName, namespace)
	}

	onConfigMapChange := func() {
		log.Info("TLS configuration changed; exiting so the pod restarts with the new settings")
		os.Exit(0)
	}

	return sdktls.StartTLSConfigMapWatcher(ctx, kubeClient, namespace, onConfigMapChange)
}

// canWatch checks list/watch access to a resource via SelfSubjectAccessReview, which needs no
// RBAC of its own, instead of finding out the hard way from a watcher that hangs rather than
// erroring on missing RBAC.
func canWatch(
	ctx context.Context, kubeClient kubernetes.Interface, attrs authorizationv1.ResourceAttributes,
) (bool, error) {
	for _, verb := range []string{"list", "watch"} {
		attrs.Verb = verb

		reviewCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		review := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &attrs},
		}

		result, err := kubeClient.AuthorizationV1().SelfSubjectAccessReviews().Create(
			reviewCtx, review, metav1.CreateOptions{})

		cancel()

		if err != nil {
			return false, fmt.Errorf("failed to check %s permission on %s: %w", verb, attrs.Resource, err)
		}

		if !result.Status.Allowed {
			return false, nil
		}
	}

	return true, nil
}

// splitTLSGroups splits the comma-separated --tls-groups value into group names.
func splitTLSGroups(groups string) []configv1.TLSGroup {
	var parsed []configv1.TLSGroup

	for group := range strings.SplitSeq(groups, ",") {
		group = strings.TrimSpace(group)
		if group != "" {
			parsed = append(parsed, configv1.TLSGroup(group))
		}
	}

	return parsed
}

// readAPIServerTLSProfileSpec fetches the APIServer's TLS profile spec using a client built from cfg.
func readAPIServerTLSProfileSpec(
	ctx context.Context, cfg *rest.Config,
) (spec configv1.TLSProfileSpec, watchable bool) {
	if cfg == nil {
		return configv1.TLSProfileSpec{}, false
	}

	apiServerCfg := rest.CopyConfig(cfg)
	if apiServerCfg.Timeout == 0 || apiServerCfg.Timeout > 10*time.Second {
		apiServerCfg.Timeout = 10 * time.Second
	}

	apiServerClient, err := client.New(apiServerCfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "Failed to create a client for the APIServer resource")

		return configv1.TLSProfileSpec{}, false
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return fetchAPIServerTLSProfileSpec(fetchCtx, apiServerClient)
}

// fetchAPIServerTLSProfileSpec returns the resolved spec and whether it can be watched. It returns
// false when the profile is unavailable, forbidden, or unreadable, since a watcher that cannot sync
// would stop the manager.
func fetchAPIServerTLSProfileSpec(
	ctx context.Context, apiServerClient client.Client,
) (spec configv1.TLSProfileSpec, watchable bool) {
	spec, err := openshifttls.FetchAPIServerTLSProfile(ctx, apiServerClient)
	switch {
	case err == nil:
		return spec, true
	case meta.IsNoMatchError(err) || apierrors.IsNotFound(err):
		log.Info("The APIServer TLS Profile is not served by this cluster; using Go TLS defaults")

		return configv1.TLSProfileSpec{}, false
	case apierrors.IsForbidden(err):
		log.Info("Access to the APIServer TLS Profile is forbidden; using Go TLS defaults")

		return configv1.TLSProfileSpec{}, false
	default:
		log.Error(err, "Failed to read the APIServer TLS Profile; "+
			"using Go TLS defaults and skipping the watch")

		return configv1.TLSProfileSpec{}, false
	}
}

// setupAPIServerTLSWatcher registers a controller that restarts the process when the APIServer
// TLS security profile changes. controller-runtime retries informer discovery until the resource
// is available, so this must run after manager construction. The watch is skipped when list/watch
// is denied, since the informer would never sync and would stop the manager.
func setupAPIServerTLSWatcher(
	ctx context.Context, mgr ctrl.Manager, initialSpec configv1.TLSProfileSpec,
) error {
	allowed, err := canWatch(ctx, kubernetes.NewForConfigOrDie(mgr.GetConfig()),
		authorizationv1.ResourceAttributes{Group: "config.openshift.io", Resource: "apiservers"})
	if err != nil || !allowed {
		log.Info("Skipping the APIServer TLS profile watch; using the resolved TLS settings",
			"allowed", allowed, "error", err)

		return nil
	}

	watcher := &openshifttls.SecurityProfileWatcher{
		Client:                mgr.GetClient(),
		InitialTLSProfileSpec: initialSpec,
		OnProfileChange:       onTLSProfileChange,
	}

	return watcher.SetupWithManager(mgr)
}

func onTLSProfileChange(_ context.Context, old, current configv1.TLSProfileSpec) {
	if slices.Equal(old.Groups, current.Groups) {
		return
	}

	log.Info("The APIServer TLS security profile changed; " +
		"exiting to apply the new settings")

	os.Exit(0)
}
