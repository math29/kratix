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

package controller_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/syntasso/kratix/api/v1alpha1"
	"github.com/syntasso/kratix/internal/controller"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// rbacTestClient returns a fresh fake client for RBAC tests that is isolated
// from the shared fakeK8sClient used by the PromiseReconciler integration tests.
func rbacTestClient() *fake.ClientBuilder {
	return fake.NewClientBuilder().WithScheme(scheme.Scheme)
}

var _ = Describe("RBAC", func() {
	var (
		rbacCtx context.Context
		cfg     controller.RBACConfig
	)

	BeforeEach(func() {
		rbacCtx = context.Background()
		cfg = controller.RBACConfig{
			Enabled: true,
			AggregationLabels: controller.RBACAggregationLabels{
				ToPlatformEngineer: "kratix.rbac/aggregate-to-platform-engineer",
				ToDeveloper:        "kratix.rbac/aggregate-to-developer",
			},
			AggregateRoles: controller.RBACAggregateRolesConfig{
				PlatformEngineer: controller.RBACRoleConfig{
					Name:   "kratix:platform-engineer",
					Create: true,
				},
				Developer: controller.RBACRoleConfig{
					Name:   "kratix:developer",
					Create: true,
				},
			},
			PerPromise: controller.RBACPerPromiseConfig{
				PlatformEngineerRole: true,
				DeveloperRole:        true,
			},
		}
	})

	// ─── BootstrapAggregateRBAC ──────────────────────────────────────────────

	Describe("BootstrapAggregateRBAC", func() {
		When("RBAC is disabled", func() {
			It("does nothing", func() {
				disabledCfg := controller.RBACConfig{Enabled: false}
				kClient := rbacTestClient().Build()

				Expect(controller.BootstrapAggregateRBAC(rbacCtx, kClient, &disabledCfg)).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(kClient.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(BeEmpty())
			})
		})

		When("cfg is nil", func() {
			It("does nothing and does not panic", func() {
				kClient := rbacTestClient().Build()
				Expect(controller.BootstrapAggregateRBAC(rbacCtx, kClient, nil)).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(kClient.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(BeEmpty())
			})
		})

		When("both aggregate roles have Create: true", func() {
			It("creates the platform-engineer aggregate ClusterRole with the correct aggregationRule", func() {
				kClient := rbacTestClient().Build()
				Expect(controller.BootstrapAggregateRBAC(rbacCtx, kClient, &cfg)).To(Succeed())

				cr := &rbacv1.ClusterRole{}
				Expect(kClient.Get(rbacCtx, types.NamespacedName{Name: "kratix:platform-engineer"}, cr)).To(Succeed())

				Expect(cr.AggregationRule).NotTo(BeNil())
				Expect(cr.AggregationRule.ClusterRoleSelectors).To(HaveLen(1))
				Expect(cr.AggregationRule.ClusterRoleSelectors[0].MatchLabels).To(Equal(map[string]string{
					"kratix.rbac/aggregate-to-platform-engineer": "true",
				}))
				Expect(cr.Rules).To(BeNil(), "rules must be nil — owned by the k8s aggregation controller")
			})

			It("creates the developer aggregate ClusterRole with the correct aggregationRule", func() {
				kClient := rbacTestClient().Build()
				Expect(controller.BootstrapAggregateRBAC(rbacCtx, kClient, &cfg)).To(Succeed())

				cr := &rbacv1.ClusterRole{}
				Expect(kClient.Get(rbacCtx, types.NamespacedName{Name: "kratix:developer"}, cr)).To(Succeed())

				Expect(cr.AggregationRule).NotTo(BeNil())
				Expect(cr.AggregationRule.ClusterRoleSelectors[0].MatchLabels).To(Equal(map[string]string{
					"kratix.rbac/aggregate-to-developer": "true",
				}))
				Expect(cr.Rules).To(BeNil())
			})

			It("is idempotent — calling twice does not error and does not duplicate roles", func() {
				kClient := rbacTestClient().Build()
				Expect(controller.BootstrapAggregateRBAC(rbacCtx, kClient, &cfg)).To(Succeed())
				Expect(controller.BootstrapAggregateRBAC(rbacCtx, kClient, &cfg)).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(kClient.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(HaveLen(2))
			})
		})

		When("a role has Create: false", func() {
			It("skips that role", func() {
				cfg.AggregateRoles.Developer.Create = false
				kClient := rbacTestClient().Build()
				Expect(controller.BootstrapAggregateRBAC(rbacCtx, kClient, &cfg)).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(kClient.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(HaveLen(1))
				Expect(list.Items[0].Name).To(Equal("kratix:platform-engineer"))
			})
		})

		When("a role Name is empty", func() {
			It("skips that role", func() {
				cfg.AggregateRoles.PlatformEngineer.Name = ""
				kClient := rbacTestClient().Build()
				Expect(controller.BootstrapAggregateRBAC(rbacCtx, kClient, &cfg)).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(kClient.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(HaveLen(1))
				Expect(list.Items[0].Name).To(Equal("kratix:developer"))
			})
		})

		When("a role's aggregation label key is empty", func() {
			It("skips that role", func() {
				cfg.AggregationLabels.ToPlatformEngineer = ""
				kClient := rbacTestClient().Build()
				Expect(controller.BootstrapAggregateRBAC(rbacCtx, kClient, &cfg)).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(kClient.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(HaveLen(1))
				Expect(list.Items[0].Name).To(Equal("kratix:developer"))
			})
		})
	})

	// ─── createPerPromiseRBACRoles ───────────────────────────────────────────

	Describe("PromiseReconciler.createPerPromiseRBACRoles (via reconciliation)", func() {
		var (
			testPromise *v1alpha1.Promise
		)

		BeforeEach(func() {
			testPromise = &v1alpha1.Promise{
				ObjectMeta: metav1.ObjectMeta{Name: "redis"},
			}
		})

		buildReconciler := func(kClient *fake.ClientBuilder, rbacCfg controller.RBACConfig) *controller.PromiseReconciler {
			return &controller.PromiseReconciler{
				Client:     kClient.Build(),
				Log:        l,
				RBACConfig: rbacCfg,
			}
		}

		When("RBAC is disabled", func() {
			It("creates no companion ClusterRoles", func() {
				disabledCfg := cfg
				disabledCfg.Enabled = false
				r := buildReconciler(rbacTestClient(), disabledCfg)

				Expect(r.CreatePerPromiseRBACRolesForTest(rbacCtx, testPromise, "marketplace.kratix.io", "redis")).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(r.Client.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(BeEmpty())
			})
		})

		When("both PerPromise flags are true", func() {
			It("creates the platform-engineer companion ClusterRole", func() {
				r := buildReconciler(rbacTestClient(), cfg)
				Expect(r.CreatePerPromiseRBACRolesForTest(rbacCtx, testPromise, "marketplace.kratix.io", "redis")).To(Succeed())

				cr := &rbacv1.ClusterRole{}
				Expect(r.Client.Get(rbacCtx, types.NamespacedName{Name: "kratix:platform-engineer:redis"}, cr)).To(Succeed())

				Expect(cr.Labels).To(HaveKeyWithValue("kratix.rbac/aggregate-to-platform-engineer", "true"))
				Expect(cr.Labels).To(HaveKeyWithValue(v1alpha1.PromiseNameLabel, "redis"))
				Expect(cr.Rules).To(HaveLen(1))
				Expect(cr.Rules[0].Verbs).To(ConsistOf("get", "list", "watch"))
				Expect(cr.Rules[0].Resources).To(ConsistOf("redis"))
				Expect(cr.Rules[0].APIGroups).To(ConsistOf("marketplace.kratix.io"))
			})

			It("creates the developer companion ClusterRole", func() {
				r := buildReconciler(rbacTestClient(), cfg)
				Expect(r.CreatePerPromiseRBACRolesForTest(rbacCtx, testPromise, "marketplace.kratix.io", "redis")).To(Succeed())

				cr := &rbacv1.ClusterRole{}
				Expect(r.Client.Get(rbacCtx, types.NamespacedName{Name: "kratix:developer:redis"}, cr)).To(Succeed())

				Expect(cr.Labels).To(HaveKeyWithValue("kratix.rbac/aggregate-to-developer", "true"))
				Expect(cr.Labels).To(HaveKeyWithValue(v1alpha1.PromiseNameLabel, "redis"))

				// CRUD rule on the Promise resource
				Expect(cr.Rules[0].Verbs).To(ConsistOf("create", "get", "list", "watch", "update", "patch", "delete"))
				// Status read rule
				Expect(cr.Rules[1].Resources).To(ConsistOf("redis/status"))
				Expect(cr.Rules[1].Verbs).To(ConsistOf("get"))
				// ResourceBinding read rule
				Expect(cr.Rules[2].Resources).To(ConsistOf("resourcebindings"))
				Expect(cr.Rules[2].APIGroups).To(ConsistOf(v1alpha1.GroupVersion.Group))
			})

			It("is idempotent — calling twice does not error or duplicate rules", func() {
				r := buildReconciler(rbacTestClient(), cfg)
				Expect(r.CreatePerPromiseRBACRolesForTest(rbacCtx, testPromise, "marketplace.kratix.io", "redis")).To(Succeed())
				Expect(r.CreatePerPromiseRBACRolesForTest(rbacCtx, testPromise, "marketplace.kratix.io", "redis")).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(r.Client.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(HaveLen(2))
			})

			It("creates distinct companion roles for distinct Promises", func() {
				r := buildReconciler(rbacTestClient(), cfg)
				promiseA := &v1alpha1.Promise{ObjectMeta: metav1.ObjectMeta{Name: "redis"}}
				promiseB := &v1alpha1.Promise{ObjectMeta: metav1.ObjectMeta{Name: "postgres"}}

				Expect(r.CreatePerPromiseRBACRolesForTest(rbacCtx, promiseA, "marketplace.kratix.io", "redis")).To(Succeed())
				Expect(r.CreatePerPromiseRBACRolesForTest(rbacCtx, promiseB, "marketplace.kratix.io", "postgres")).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(r.Client.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(HaveLen(4))

				names := make([]string, 0, 4)
				for _, cr := range list.Items {
					names = append(names, cr.Name)
				}
				Expect(names).To(ConsistOf(
					"kratix:platform-engineer:redis",
					"kratix:developer:redis",
					"kratix:platform-engineer:postgres",
					"kratix:developer:postgres",
				))
			})
		})

		When("PlatformEngineerRole is false", func() {
			It("only creates the developer companion ClusterRole", func() {
				noPECfg := cfg
				noPECfg.PerPromise.PlatformEngineerRole = false
				r := buildReconciler(rbacTestClient(), noPECfg)
				Expect(r.CreatePerPromiseRBACRolesForTest(rbacCtx, testPromise, "marketplace.kratix.io", "redis")).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(r.Client.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(HaveLen(1))
				Expect(list.Items[0].Name).To(Equal("kratix:developer:redis"))
			})
		})

		When("DeveloperRole is false", func() {
			It("only creates the platform-engineer companion ClusterRole", func() {
				noDevCfg := cfg
				noDevCfg.PerPromise.DeveloperRole = false
				r := buildReconciler(rbacTestClient(), noDevCfg)
				Expect(r.CreatePerPromiseRBACRolesForTest(rbacCtx, testPromise, "marketplace.kratix.io", "redis")).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(r.Client.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(HaveLen(1))
				Expect(list.Items[0].Name).To(Equal("kratix:platform-engineer:redis"))
			})
		})

		When("the aggregate role Name is empty", func() {
			It("skips that companion role", func() {
				noNameCfg := cfg
				noNameCfg.AggregateRoles.Developer.Name = ""
				r := buildReconciler(rbacTestClient(), noNameCfg)
				Expect(r.CreatePerPromiseRBACRolesForTest(rbacCtx, testPromise, "marketplace.kratix.io", "redis")).To(Succeed())

				list := &rbacv1.ClusterRoleList{}
				Expect(r.Client.List(rbacCtx, list)).To(Succeed())
				Expect(list.Items).To(HaveLen(1))
				Expect(list.Items[0].Name).To(Equal("kratix:platform-engineer:redis"))
			})
		})
	})
})
