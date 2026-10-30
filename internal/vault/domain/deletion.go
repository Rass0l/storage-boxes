package domain

type BoxDeletionState string

const (
	BoxDeletionRequested BoxDeletionState = "requested"
	BoxDeletionRevoking  BoxDeletionState = "revoking"
	BoxDeletionDeleting  BoxDeletionState = "deleting"
	BoxDeletionDeleted   BoxDeletionState = "deleted"
	BoxDeletionFailed    BoxDeletionState = "failed"
)
