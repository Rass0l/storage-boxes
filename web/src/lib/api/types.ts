export type ErrorResponse = {
  error: {
    code: string
    message: string
    meta?: Record<string, unknown>
  }
}
