package controller

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/syntasso/kratix/api/v1alpha1"
	"github.com/syntasso/kratix/lib/workflow"
	"github.com/syntasso/kratix/lib/writers"
)

func SetReconcileConfigureWorkflow(f func(workflow.Opts) (bool, error)) {
	reconcileConfigure = f
}

func SetReconcileDeleteWorkflow(f func(workflow.Opts) (bool, error)) {
	reconcileDelete = f
}

func SetNewS3Writer(f func(logger logr.Logger, stateStoreSpec v1alpha1.BucketStateStoreSpec, destinationPath string,
	creds map[string][]byte) (writers.StateStoreWriter, error)) {
	newS3Writer = f
}

func SetNewGitWriter(f func(logger logr.Logger, stateStoreSpec v1alpha1.GitStateStoreSpec, destinationPath string,
	creds map[string][]byte) (writers.StateStoreWriter, error)) {
	newGitWriter = f
}

// CreatePerPromiseRBACRolesForTest exposes the private createPerPromiseRBACRoles method for
// unit testing without going through a full Promise reconciliation loop.
func (r *PromiseReconciler) CreatePerPromiseRBACRolesForTest(
	ctx context.Context,
	promise *v1alpha1.Promise,
	group, plural string,
) error {
	return r.createPerPromiseRBACRoles(ctx, promise, group, plural)
}
