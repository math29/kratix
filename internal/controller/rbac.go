/*
Copyright 2021 Syntasso.

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

package controller

// This file implements the Kratix aggregation-based RBAC model.
//
// Design overview
// ───────────────
//  Static aggregate ClusterRoles (created once at startup via BootstrapAggregateRBAC):
//    <platformEngineerName> – combined role for platform operators and Promise authors;
//                             rules[] owned by the k8s RBAC aggregation controller
//    <developerName>        – namespace-scoped role for resource requestors (RoleBinding only)
//
//  Per-Promise companion ClusterRoles (created by PromiseReconciler on every reconcile):
//    <platformEngineerName>:<promiseName> – get/list/watch on the Promise CRD;
//                                           labelled → platform-engineer aggregate
//    <developerName>:<promiseName>        – CRUD on the Promise CRD + resourcebindings read;
//                                           labelled → developer aggregate
//
// Cleanup
// ───────
// Companion roles carry the Promise shared label (kratix.io/promise-name=<name>).
// The existing deleteDynamicControllerAndWorkflowResources label-sweep therefore
// reaps them automatically — no new finalizer is required.

import (
	"context"
	"fmt"

	"github.com/syntasso/kratix/api/v1alpha1"
	"github.com/syntasso/kratix/internal/logging"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// ─── Configuration types ───────────────────────────────────────────────────

// RBACConfig controls Kratix's aggregation-based RBAC feature.
// Serialised from the kratix-platform-system/kratix ConfigMap under the "rbac" key.
type RBACConfig struct {
	// Enabled activates the RBAC aggregation feature. Default: false.
	Enabled bool `json:"enabled,omitempty"`

	// AggregationLabels are the label keys used to wire per-Promise companion ClusterRoles
	// into the aggregate ClusterRoles via Kubernetes aggregation.
	AggregationLabels RBACAggregationLabels `json:"aggregationLabels,omitempty"`

	// AggregateRoles controls which static aggregate ClusterRoles Kratix creates at startup.
	AggregateRoles RBACAggregateRolesConfig `json:"aggregateRoles,omitempty"`

	// PerPromise controls which companion ClusterRoles are created per Promise with an API.
	PerPromise RBACPerPromiseConfig `json:"perPromise,omitempty"`
}

// RBACAggregationLabels holds the label keys used for Kubernetes ClusterRole aggregation.
// The values must match the selectors on the corresponding aggregate ClusterRoles.
type RBACAggregationLabels struct {
	// ToPlatformEngineer is applied to roles that should aggregate into the platform-engineer role.
	ToPlatformEngineer string `json:"toPlatformEngineer,omitempty"`
	// ToDeveloper is applied to per-Promise roles that should aggregate into the developer role.
	ToDeveloper string `json:"toDeveloper,omitempty"`
}

// RBACAggregateRolesConfig names the two aggregate ClusterRoles and whether to create them.
type RBACAggregateRolesConfig struct {
	// PlatformEngineer is the aggregate role for platform operators and Promise authors.
	PlatformEngineer RBACRoleConfig `json:"platformEngineer,omitempty"`
	// Developer is the aggregate role for resource requestors (used via RoleBinding per
	// namespace only; never as a ClusterRoleBinding).
	Developer RBACRoleConfig `json:"developer,omitempty"`
}

// RBACPerPromiseConfig controls per-Promise companion ClusterRole creation.
type RBACPerPromiseConfig struct {
	// PlatformEngineerRole creates <platformEngineerName>:<promiseName> per Promise, labelled
	// to aggregate into the platform-engineer aggregate role.
	PlatformEngineerRole bool `json:"platformEngineerRole,omitempty"`

	// DeveloperRole creates <developerName>:<promiseName> per Promise, labelled to
	// aggregate into the developer aggregate role.
	DeveloperRole bool `json:"developerRole,omitempty"`
}

// RBACRoleConfig names a ClusterRole and whether Kratix should create/maintain it.
type RBACRoleConfig struct {
	// Name is the ClusterRole name.
	Name string `json:"name,omitempty"`
	// Create causes Kratix to create (or update) this ClusterRole at startup.
	Create bool `json:"create,omitempty"`
}

// ─── Per-Promise companion roles ───────────────────────────────────────────

// createPerPromiseRBACRoles creates the companion ClusterRoles for a Promise that has an API.
//
// Companion roles carry the Promise's shared label (kratix.io/promise-name=<name>) so they
// are automatically reaped by the existing label-based cleanup in
// deleteDynamicControllerAndWorkflowResources when the Promise is deleted.
func (r *PromiseReconciler) createPerPromiseRBACRoles(
	ctx context.Context,
	promise *v1alpha1.Promise,
	group, plural string,
) error {
	if !r.RBACConfig.Enabled {
		return nil
	}

	cfg := r.RBACConfig
	promiseLabels := promise.GenerateSharedLabels()
	logger := r.Log.WithValues("promise", promise.GetName())

	// ── Platform-engineer companion role ────────────────────────────────
	// Grants get/list/watch on this Promise's CRD to platform engineers.
	if cfg.PerPromise.PlatformEngineerRole && cfg.AggregateRoles.PlatformEngineer.Name != "" {
		peName := cfg.AggregateRoles.PlatformEngineer.Name + ":" + promise.GetName()
		aggLabels := aggregationLabelsFor(cfg.AggregationLabels.ToPlatformEngineer)
		rules := []rbacv1.PolicyRule{
			{
				APIGroups: []string{group},
				Resources: []string{plural},
				Verbs:     []string{"get", "list", "watch"},
			},
		}
		logging.Debug(logger, "creating/updating platform-engineer companion ClusterRole", "name", peName)
		if err := createOrUpdateCompanionClusterRole(ctx, r.Client, peName, aggLabels, promiseLabels, rules); err != nil {
			return fmt.Errorf("creating platform-engineer companion ClusterRole for Promise %s: %w", promise.GetName(), err)
		}
	}

	// ── Developer companion role ─────────────────────────────────────────
	// Grants full CRUD on this Promise's CRD to resource requestors.
	// Intended for use via RoleBinding in the requester namespace — never cluster-wide.
	if cfg.PerPromise.DeveloperRole && cfg.AggregateRoles.Developer.Name != "" {
		devName := cfg.AggregateRoles.Developer.Name + ":" + promise.GetName()
		aggLabels := aggregationLabelsFor(cfg.AggregationLabels.ToDeveloper)
		rules := []rbacv1.PolicyRule{
			{
				APIGroups: []string{group},
				Resources: []string{plural},
				Verbs:     []string{"create", "get", "list", "watch", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{group},
				Resources: []string{plural + "/status"},
				Verbs:     []string{"get"},
			},
			{
				// Allow developers to observe provisioning status via ResourceBindings.
				APIGroups: []string{v1alpha1.GroupVersion.Group},
				Resources: []string{"resourcebindings"},
				Verbs:     []string{"get", "list", "watch"},
			},
		}
		logging.Debug(logger, "creating/updating developer companion ClusterRole", "name", devName)
		if err := createOrUpdateCompanionClusterRole(ctx, r.Client, devName, aggLabels, promiseLabels, rules); err != nil {
			return fmt.Errorf("creating developer companion ClusterRole for Promise %s: %w", promise.GetName(), err)
		}
	}

	return nil
}

// aggregationLabelsFor builds a label map setting each non-empty key to "true".
func aggregationLabelsFor(keys ...string) map[string]string {
	lbs := make(map[string]string, len(keys))
	for _, k := range keys {
		if k != "" {
			lbs[k] = "true"
		}
	}
	return lbs
}

// createOrUpdateCompanionClusterRole idempotently creates or updates a companion ClusterRole.
// Labels are merged in order: existing labels → promiseLabels → aggregationLabels.
// The aggregation labels intentionally overwrite any conflicting existing labels.
func createOrUpdateCompanionClusterRole(
	ctx context.Context,
	kClient client.Client,
	name string,
	aggregationLabels map[string]string,
	promiseLabels map[string]string,
	rules []rbacv1.PolicyRule,
) error {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, kClient, cr, func() error {
		cr.Rules = rules
		cr.Labels = labels.Merge(labels.Merge(cr.Labels, promiseLabels), aggregationLabels)
		return nil
	})
	return err
}

// ─── Startup bootstrap ─────────────────────────────────────────────────────

// BootstrapAggregateRBAC creates the static aggregate ClusterRoles whose rules[] field
// is owned and populated by the Kubernetes RBAC aggregation controller.
// It is called once at controller startup and is idempotent. Safe to call on every
// leader election in a multi-replica setup.
func BootstrapAggregateRBAC(ctx context.Context, kClient client.Client, cfg *RBACConfig) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	if err := bootstrapAggregateClusterRoles(ctx, kClient, cfg); err != nil {
		return fmt.Errorf("bootstrapping aggregate ClusterRoles: %w", err)
	}

	return nil
}

// bootstrapAggregateClusterRoles creates the two empty aggregate ClusterRoles.
// Their rules[] field is intentionally nil — owned by the Kubernetes RBAC aggregation
// controller, which populates it from all ClusterRoles that carry the matching label.
func bootstrapAggregateClusterRoles(ctx context.Context, kClient client.Client, cfg *RBACConfig) error {
	type spec struct {
		role        RBACRoleConfig
		selectorKey string
	}

	specs := []spec{
		{role: cfg.AggregateRoles.PlatformEngineer, selectorKey: cfg.AggregationLabels.ToPlatformEngineer},
		{role: cfg.AggregateRoles.Developer, selectorKey: cfg.AggregationLabels.ToDeveloper},
	}

	for _, s := range specs {
		if !s.role.Create || s.role.Name == "" || s.selectorKey == "" {
			continue
		}

		cr := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: s.role.Name},
		}
		if _, err := controllerutil.CreateOrUpdate(ctx, kClient, cr, func() error {
			cr.AggregationRule = &rbacv1.AggregationRule{
				ClusterRoleSelectors: []metav1.LabelSelector{
					{MatchLabels: map[string]string{s.selectorKey: "true"}},
				},
			}
			// Leave rules nil: the Kubernetes controller owns this field.
			cr.Rules = nil
			return nil
		}); err != nil {
			return fmt.Errorf("creating aggregate ClusterRole %s: %w", s.role.Name, err)
		}
	}

	return nil
}


