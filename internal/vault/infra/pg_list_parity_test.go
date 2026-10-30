package infra

// Parity between the memory and pg BoxRepository implementations used
// to be guarded by grepping `pg_boxes.go` for literal substrings. That
// caught text drift (someone deleting the WHERE clause) but nothing
// semantic — a query that SELECT'd the filter column without
// actually filtering on it would have passed, and the grep couldn't
// see interaction bugs across methods (e.g. SoftDelete on an unknown
// id that silently returned nil).
//
// Behavioral parity is now enforced by `apptest.BoxRepositoryContract`
// (see internal/vault/apptest/box_contract.go). It runs against:
//
//   - the memory repo, in `memory_box_contract_test.go` at unit-test
//     speed; and
//   - the pg repo, in `test/e2e/compose_pg_direct_contract_test.go`,
//     gated by the `compose_e2e` build tag so it only runs under the
//     live compose stack.
//
// Both suites exercise the same scenarios, so any drift between the
// implementations fails the test instead of the grep — and a new
// invariant only needs to be added once, in the shared contract,
// instead of separately in the memory and pg test files.
