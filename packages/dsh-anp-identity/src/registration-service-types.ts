/** Default for new registrations only; existing identities retain their own origin. */
export const DEFAULT_REGISTRATION_ORIGIN = 'https://awiki.me';
export interface RegistrationServiceSettings {
  readonly origin: string;
  readonly version: number;
}
export interface UpdateRegistrationServiceSettings {
  readonly origin: string;
  readonly expectedVersion: number;
}
