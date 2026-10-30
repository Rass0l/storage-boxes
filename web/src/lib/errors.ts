export function toErrorMessage(input: unknown): string {
  if (input instanceof Error) return input.message
  return 'unknown error'
}
