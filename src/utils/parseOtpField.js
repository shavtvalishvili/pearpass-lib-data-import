/**
 * Lightweight OTP URI / secret parser for the import library.
 * No external dependencies — runs in the renderer.
 */

/**
 * @param {string} input
 * @returns {boolean}
 */
export const isOtpauthUri = (input) =>
  typeof input === 'string' && input.startsWith('otpauth://')

/**
 * Parses an otpauth:// URI into a structured OTP config object.
 * @param {string} uri
 * @returns {object|null}
 */
export const parseOtpauthUri = (uri) => {
  try {
    const url = new URL(uri)
    const type = url.host.toUpperCase() // 'totp' or 'hotp'
    if (type !== 'TOTP' && type !== 'HOTP') return null

    const secret = url.searchParams.get('secret')
    if (!secret) return null

    const config = {
      secret: secret.toUpperCase(),
      type,
      algorithm: (url.searchParams.get('algorithm') || 'SHA1').toUpperCase(),
      digits: parseInt(url.searchParams.get('digits') || '6', 10)
    }

    if (type === 'TOTP') {
      config.period = parseInt(url.searchParams.get('period') || '30', 10)
    } else {
      config.counter = parseInt(url.searchParams.get('counter') || '0', 10)
    }

    const issuer = url.searchParams.get('issuer')
    if (issuer) config.issuer = issuer

    // Label is the path component (after /)
    const label = decodeURIComponent(url.pathname.slice(1))
    if (label) config.label = label

    return config
  } catch {
    return null
  }
}

/**
 * Parses OTP input: otpauth:// URI, raw Base32 secret, or KeePass-specific formats.
 * Returns null if input is empty or unparseable.
 * @param {string} input
 * @returns {object|null}
 */
export const parseOtpField = (input) => {
  if (!input || typeof input !== 'string') return null

  const trimmed = input.trim()
  if (!trimmed) return null

  if (isOtpauthUri(trimmed)) {
    return parseOtpauthUri(trimmed)
  }

  // Raw Base32 secret — default to TOTP / SHA1 / 6 digits / 30s
  return {
    secret: trimmed.toUpperCase(),
    type: 'TOTP',
    algorithm: 'SHA1',
    digits: 6,
    period: 30
  }
}

/**
 * Parses KeePass TOTP fields.
 * KeePass stores TOTP as separate "TOTP Settings" (e.g., "30;6") and "TOTP Seed" fields,
 * or as a single "otp" / "TimeOtp-Secret-Base32" field with a URI or raw secret.
 * @param {object} totpFields - Map of TOTP field key -> value
 * @returns {object|null}
 */
export const parseKeePassTotpFields = (totpFields) => {
  if (!totpFields || Object.keys(totpFields).length === 0) return null

  // If there's an 'otp' field, it's usually a full otpauth:// URI
  if (totpFields.otp) {
    return parseOtpField(totpFields.otp)
  }

  // TimeOtp-Secret-Base32 is a raw Base32 secret
  if (totpFields['TimeOtp-Secret-Base32']) {
    return parseOtpField(totpFields['TimeOtp-Secret-Base32'])
  }

  // KeePass classic: "TOTP Seed" + optional "TOTP Settings"
  const seed = totpFields['TOTP Seed']
  if (!seed) return null

  const config = parseOtpField(seed)
  if (!config) return null

  const settings = totpFields['TOTP Settings']
  if (settings) {
    const parts = settings.split(';')
    if (parts.length >= 1) {
      const period = parseInt(parts[0], 10)
      if (!isNaN(period) && period > 0) config.period = period
    }
    if (parts.length >= 2) {
      const digits = parseInt(parts[1], 10)
      if (!isNaN(digits) && digits >= 4 && digits <= 10) config.digits = digits
    }
  }

  return config
}
