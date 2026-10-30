# Health and Readiness

Each runtime has a different readiness contract.

API runtime:
- health means the process is running
- readiness means config loaded, database reachable, and HTTP handler graph initialized

Worker runtime:
- health means the process loop is alive
- readiness means database and storage paths are available for job execution

Share gateway:
- health means HTTP service is alive
- readiness means share-stage storage and audit emission dependencies are available

Migration runtime:
- runs to completion rather than staying ready
- must still validate configuration before attempting schema work
