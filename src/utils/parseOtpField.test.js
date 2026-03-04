import {
  isOtpauthUri,
  parseOtpauthUri,
  parseOtpField,
  parseKeePassTotpFields
} from './parseOtpField'

describe('isOtpauthUri', () => {
  it('returns true for otpauth URIs', () => {
    expect(isOtpauthUri('otpauth://totp/Test?secret=ABC')).toBe(true)
  })

  it('returns false for non-URIs', () => {
    expect(isOtpauthUri('JBSWY3DPEHPK3PXP')).toBe(false)
    expect(isOtpauthUri(null)).toBe(false)
  })
})

describe('parseOtpauthUri', () => {
  it('parses a TOTP URI', () => {
    const result = parseOtpauthUri(
      'otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60'
    )

    expect(result).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'TOTP',
      algorithm: 'SHA256',
      digits: 8,
      period: 60,
      issuer: 'Example',
      label: 'Example:alice@example.com'
    })
  })

  it('parses an HOTP URI with counter', () => {
    const result = parseOtpauthUri(
      'otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=5'
    )

    expect(result.type).toBe('HOTP')
    expect(result.counter).toBe(5)
    expect(result.period).toBeUndefined()
  })

  it('applies defaults for missing params', () => {
    const result = parseOtpauthUri(
      'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP'
    )

    expect(result.algorithm).toBe('SHA1')
    expect(result.digits).toBe(6)
    expect(result.period).toBe(30)
  })

  it('returns null for invalid URIs', () => {
    expect(parseOtpauthUri('not-a-uri')).toBeNull()
    expect(parseOtpauthUri('otpauth://invalid/Test?secret=ABC')).toBeNull()
  })

  it('returns null for missing secret', () => {
    expect(parseOtpauthUri('otpauth://totp/Test')).toBeNull()
  })
})

describe('parseOtpField', () => {
  it('parses raw Base32 secret with defaults', () => {
    const result = parseOtpField('JBSWY3DPEHPK3PXP')

    expect(result).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'TOTP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30
    })
  })

  it('parses otpauth:// URI', () => {
    const result = parseOtpField(
      'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=Test'
    )

    expect(result.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(result.issuer).toBe('Test')
  })

  it('returns null for empty input', () => {
    expect(parseOtpField('')).toBeNull()
    expect(parseOtpField(null)).toBeNull()
    expect(parseOtpField(undefined)).toBeNull()
  })

  it('uppercases raw secrets', () => {
    const result = parseOtpField('jbswy3dpehpk3pxp')
    expect(result.secret).toBe('JBSWY3DPEHPK3PXP')
  })
})

describe('parseKeePassTotpFields', () => {
  it('parses otp field as URI', () => {
    const result = parseKeePassTotpFields({
      otp: 'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=Test'
    })

    expect(result.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(result.issuer).toBe('Test')
  })

  it('parses TimeOtp-Secret-Base32 as raw secret', () => {
    const result = parseKeePassTotpFields({
      'TimeOtp-Secret-Base32': 'JBSWY3DPEHPK3PXP'
    })

    expect(result.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(result.type).toBe('TOTP')
  })

  it('parses TOTP Seed with TOTP Settings', () => {
    const result = parseKeePassTotpFields({
      'TOTP Seed': 'JBSWY3DPEHPK3PXP',
      'TOTP Settings': '60;8'
    })

    expect(result.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(result.period).toBe(60)
    expect(result.digits).toBe(8)
  })

  it('parses TOTP Seed without Settings', () => {
    const result = parseKeePassTotpFields({
      'TOTP Seed': 'JBSWY3DPEHPK3PXP'
    })

    expect(result.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(result.period).toBe(30)
    expect(result.digits).toBe(6)
  })

  it('returns null for empty input', () => {
    expect(parseKeePassTotpFields(null)).toBeNull()
    expect(parseKeePassTotpFields({})).toBeNull()
  })
})
