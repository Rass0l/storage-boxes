# Repository audit and patch cycles

Scope: prepare source and local container distributions for a new repository,
preserving the standard Apache 2.0 license. This is a focused repository review,
not a security certification or a completed production-readiness assessment.

## Cycle 1 — License consistency

Found: package metadata had no license identifier, and runtime images copied
only binaries/assets, leaving out the new project LICENSE and NOTICE.

Patched: added `Apache-2.0` package metadata and image labels, copied LICENSE
and NOTICE into all five project runtime images, and documented licensing,
attribution, warranty/liability limits, and contribution ownership without
adding restrictions to the standard license.

Checked: the LICENSE text matched the official Apache download byte-for-byte
(SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`).
Package metadata and lockfile agree. Runtime artifact checks are recorded in
the final cycle after rebuilding the images.

## Cycle 2 — README, use cases, and version accuracy

Found: the README had no use-case section, package metadata still reported
0.4.0 while OpenAPI already reported 0.5.0, and readers could confuse the
application version with the `/api/v1` contract. The manual share form and
server-visible metadata needed clearer explanation.

Patched: established VERSION 0.5.0 and an unreleased changelog, aligned package
metadata and current operator docs, added supported use cases, and made the
server-side encryption, metadata visibility, manual share workflow, and audit
limitations explicit. Historical stage documents remain historical.

Checked: version metadata was compared against VERSION and README links were
resolved against local files. Existing behavior was checked against sharing
routes, the share form, and the metadata-visibility architecture decision.

## Cycle 3 — Secret handling and recovery claims

Found: the backup manifest's supposed redaction retained the DSN's username
and password. Recovery documentation incorrectly claimed a concurrent purge
could not invalidate a database-before-blobs backup. The source exporter
missed very short credential values and only checked a file's own link flag.

Patched: removed the DSN entirely from the manifest, documented stopped
writers/purgers as the snapshot precondition, added a real-script regression
test for emitted manifest/log content, checked credential filenames without
case sensitivity, included short local secrets in exact matching, checked
linked parent paths, and required release files plus an unchanged Apache
license before export.

Checked: the manifest regression runs in the final containerized suite; an
isolated short-secret canary verifies the exporter rejects a leaking candidate
before its scanner runs. The canary is synthetic and removed after the check.

## Cycle 4 — Attribution, contributions, and security communication

Found: NOTICE referred generally to third-party terms without preserving their
actual application dependency license texts. There was no security reporting
guidance or explanation of contributor rights and incoming licensing terms.

Patched: copied the installed licenses for the Go toolchain, eight Go modules,
and eight frontend production dependencies into THIRD_PARTY_NOTICES.md;
linked it from NOTICE and the README; documented Apache section 5 contribution
terms without copyright assignment; and added honest security-reporting and
deployment-boundary guidance without inventing an email address, support SLA,
security certification, or additional license restrictions.

Checked: dependency versions were compared with go.mod and the production
package-lock closure, all 17 attribution sections were present, and existing
copyright notices were retained. The public reporting flow is described
conditionally because the new repository has not been created yet.

## Cycle 5 — Distribution and regression checks

Found: the initial runtime-copy patch did not yet include third-party notices
or image version labels. Version consistency was a one-off check, and a clean
checkout imported from Windows could lack shell executable bits needed by CI.
The final bundle inspection also identified Vite-generated browser helper
code beyond the frontend package dependency closure.

Patched: included all three license/attribution files and 0.5.0 version labels
in every project runtime image; added reusable release metadata checks to the
Windows workflow, exporter, and CI; made backend CI invoke Bash explicitly;
and corrected current recovery status after the redaction fix.
Documented PowerShell 7 as the supported Windows shell and enforced that
requirement in the metadata/export scripts that rely on its JSON support.
Added the installed Vite core license for its emitted browser helpers, making
18 attribution sections in the final file.

Validation covers rebuilt runtime image contents/labels, the backend and
frontend suites (including the manifest regression), the live persisted smoke
flow, README links, the short-secret rejection canary, and a final offline
Gitleaks plus local-credential comparison of the exported source snapshot.

Results: backend formatting/vet/build/unit/integration/migration checks passed,
including the executed backup-manifest regression; TypeScript/build and all 19
frontend tests passed; each of the five runtime images had matching license,
notice, and dependency-attribution files plus 0.5.0/Apache-2.0 labels; the live
sharing smoke and prior-sample decryption passed; README links and release
metadata passed; the final exported source passed offline Gitleaks and exact
local credential matching, including the external Git token file.

## Remaining boundary

No repository, tag, or release has been created or pushed. Apache 2.0 remains
unchanged. These cycles do not replace a full application security audit,
base-image/dependency vulnerability review, the separate destructive Compose
acceptance suite, Playwright coverage, or an isolated restore rehearsal.
Known runtime consistency issues remain in project-status.md.

## Subsequent public source review

The [2026-10-30 publication review](publication-readiness.md) adds dependency
advisory checks, patched toolchains/libraries/container bases, refreshed notices,
and restricted CI permissions. It supersedes the dependency versions and notice
counts recorded in the historical cycles above. Full image vulnerability analysis,
acceptance coverage, and recovery rehearsal remain separate work.
