export class DomainError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "DomainError";
  }
}

export const notFound = (resource: string): DomainError => new DomainError(404, "not_found", `${resource} was not found`);
export const conflict = (code: string, message: string, details?: Record<string, unknown>): DomainError =>
  new DomainError(409, code, message, details);
export const invalid = (code: string, message: string, details?: Record<string, unknown>): DomainError =>
  new DomainError(422, code, message, details);
export const unauthorized = (): DomainError => new DomainError(401, "invalid_agent_token", "Agent credentials are invalid or expired");
