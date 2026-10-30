# Box Deletion State Machine

The box deletion workflow is intentionally explicit because it crosses vault, shares, audit, and jobs.

States:
- `requested`
- `revoking`
- `deleting`
- `deleted`
- `failed`

Transition notes:
1. `requested` means the API accepted the deletion request and no new shares or unlock sessions should be created.
2. `revoking` means active unlock sessions and active shares are being marked for shutdown.
3. `deleting` means encrypted objects and metadata are being removed in an orchestrated order.
4. `deleted` means the workflow completed successfully and only audit evidence remains.
5. `failed` means the workflow stopped in a recoverable error state and requires an operator or retry path.

This state machine should remain the single source of truth for box deletion across later stages.
