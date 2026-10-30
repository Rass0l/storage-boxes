# Route Inventory

Authenticated API surface:
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`
- `GET /api/v1/users`
- `GET /api/v1/boxes`
- `POST /api/v1/boxes`
- `POST /api/v1/boxes/{id}/sessions`
- `DELETE /api/v1/boxes/{id}/sessions/{sessionId}`
- `GET /api/v1/boxes/{id}/files`
- `PUT /api/v1/boxes/{id}/files`
- `POST /api/v1/boxes/{id}/folders`
- `POST /api/v1/boxes/{id}/files/move`
- `GET /api/v1/shares`
- `POST /api/v1/shares`
- `GET /api/v1/audit/events`
- `GET /api/v1/admin/ping`

Public share surface:
- `GET /s/{token}`
