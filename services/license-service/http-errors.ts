export interface PublicLicenseServiceError {
  status: 400 | 403 | 413 | 500;
  code:
    | 'INVALID_REQUEST'
    | 'REQUEST_TOO_LARGE'
    | 'LICENSE_DENIED'
    | 'ARTIFACT_DENIED'
    | 'TOKEN_DENIED'
    | 'ACTIVATION_DENIED'
    | 'RECEIPT_DENIED'
    | 'RECEIPT_TRANSITION_DENIED'
    | 'INTERNAL_ERROR';
}

const deniedCodes = new Set<PublicLicenseServiceError['code']>([
  'LICENSE_DENIED',
  'ARTIFACT_DENIED',
  'TOKEN_DENIED',
  'ACTIVATION_DENIED',
  'RECEIPT_DENIED',
  'RECEIPT_TRANSITION_DENIED'
]);

const invalidFieldMessage = /^Invalid (?:licenseKey|oneTimeToken|artifactId|installId|clientPublicKeyPem|activationId|recoveryToken|receiptToken|status)\.$/;

/**
 * Convert only explicitly recognized client faults into a 4xx response. Any
 * database, filesystem, lock, signing, or other unexpected failure is a 500.
 * This distinction is part of activation recovery: clients may safely discard
 * a brand-new install identity only after a definite, non-retryable 4xx.
 */
export function publicLicenseServiceError(error: unknown): PublicLicenseServiceError {
  const message = error instanceof Error ? error.message : '';
  if (deniedCodes.has(message as PublicLicenseServiceError['code'])) {
    return { status: 403, code: message as PublicLicenseServiceError['code'] };
  }
  if (message === 'Request body is too large.') {
    return { status: 413, code: 'REQUEST_TOO_LARGE' };
  }
  if (
    message === 'INVALID_REQUEST'
    || message === 'Invalid receipt status.'
    || invalidFieldMessage.test(message)
    || error instanceof SyntaxError
  ) {
    return { status: 400, code: 'INVALID_REQUEST' };
  }
  return { status: 500, code: 'INTERNAL_ERROR' };
}
