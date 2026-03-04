import {
  parseBitwardenJson,
  parseBitwardenCSV,
  parseBitwardenData
} from './bitwarden'
import { addHttps } from '../utils/addHttps'
import { getRowsFromCsv } from '../utils/getRowsFromCsv'

jest.mock('../utils/addHttps', () => ({
  addHttps: jest.fn((url) => `https://${url.replace(/^https?:\/\//, '')}`)
}))
jest.mock('../utils/getRowsFromCsv', () => ({
  getRowsFromCsv: jest.fn()
}))

describe('parseBitwardenJson', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('parses login item', () => {
    const json = {
      folders: [{ id: '1', name: 'Personal' }],
      items: [
        {
          type: 1,
          name: 'Test Login',
          notes: 'Some notes',
          favorite: true,
          folderId: '1',
          login: {
            username: 'user',
            password: 'pass',
            uris: [{ uri: 'example.com' }]
          }
        }
      ]
    }
    const result = parseBitwardenJson(json)
    expect(result).toEqual([
      {
        type: 'login',
        folder: 'Personal',
        isFavorite: true,
        data: {
          title: 'Test Login',
          username: 'user',
          password: 'pass',
          note: 'Some notes',
          websites: ['https://example.com'],
          customFields: []
        }
      }
    ])
    expect(addHttps).toHaveBeenCalledWith('example.com')
  })

  it('parses note item', () => {
    const json = {
      items: [
        {
          type: 2,
          name: 'Secure Note',
          notes: 'Note content',
          favorite: false
        }
      ]
    }
    const result = parseBitwardenJson(json)
    expect(result[0]).toMatchObject({
      type: 'note',
      data: {
        title: 'Secure Note',
        note: 'Note content',
        customFields: []
      },
      isFavorite: false
    })
  })

  it('parses credit card item', () => {
    const json = {
      items: [
        {
          type: 3,
          name: 'My Card',
          notes: 'Card note',
          card: {
            cardholderName: 'John Doe',
            number: '1234',
            expMonth: '12',
            expYear: '2025',
            code: '999'
          }
        }
      ]
    }
    const result = parseBitwardenJson(json)
    expect(result[0]).toMatchObject({
      type: 'creditCard',
      data: {
        title: 'My Card',
        name: 'John Doe',
        number: '1234',
        expireDate: '12/2025',
        securityCode: '999',
        pinCode: '',
        note: 'Card note',
        customFields: []
      }
    })
  })

  it('parses identity item', () => {
    const json = {
      items: [
        {
          type: 4,
          name: 'Identity',
          notes: 'ID note',
          identity: {
            firstName: 'Jane',
            middleName: 'Q',
            lastName: 'Public',
            email: 'jane@example.com',
            phone: '1234567890',
            address1: '123 Main St',
            address2: 'Apt 4',
            address3: '',
            postalCode: '12345',
            city: 'Metropolis',
            state: 'CA',
            country: 'USA'
          }
        }
      ]
    }
    const result = parseBitwardenJson(json)
    expect(result[0]).toMatchObject({
      type: 'identity',
      data: expect.objectContaining({
        title: 'Identity',
        fullName: 'Jane Q Public',
        email: 'jane@example.com',
        phoneNumber: '1234567890',
        address: '123 Main St, Apt 4',
        zip: '12345',
        city: 'Metropolis',
        region: 'CA',
        country: 'USA',
        note: 'ID note',
        customFields: []
      })
    })
  })

  it('extracts TOTP into otp field from JSON', () => {
    const json = {
      folders: [],
      items: [
        {
          type: 1,
          name: 'TOTP Login',
          login: {
            username: 'user',
            password: 'pass',
            totp: 'otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test'
          }
        }
      ]
    }
    const result = parseBitwardenJson(json)
    expect(result[0].data.otp).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'TOTP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      issuer: 'Test',
      label: 'Test:user@example.com'
    })
    expect(result[0].data.customFields).toEqual([])
  })

  it('extracts raw Base32 TOTP secret into otp field', () => {
    const json = {
      folders: [],
      items: [
        {
          type: 1,
          name: 'Raw TOTP',
          login: {
            username: 'user',
            password: 'pass',
            totp: 'JBSWY3DPEHPK3PXP'
          }
        }
      ]
    }
    const result = parseBitwardenJson(json)
    expect(result[0].data.otp).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'TOTP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30
    })
  })

  it('parses unknown type as custom', () => {
    const json = {
      items: [
        {
          type: 99,
          name: 'Unknown'
        }
      ]
    }
    const result = parseBitwardenJson(json)
    expect(result[0]).toMatchObject({
      type: 'custom',
      data: {
        title: 'Unknown',
        customFields: []
      }
    })
  })
})

describe('parseBitwardenCSV', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('parses login row', () => {
    getRowsFromCsv.mockReturnValue([
      [
        'folder',
        'favorite',
        'type',
        'name',
        'notes',
        'login_username',
        'login_password',
        'login_uri'
      ],
      [
        'Personal',
        'true',
        'login',
        'Test Login',
        'Some notes',
        'user',
        'pass',
        'example.com'
      ]
    ])
    const result = parseBitwardenCSV('csvText')
    expect(result).toEqual([
      {
        type: 'login',
        folder: 'Personal',
        isFavorite: true,
        data: {
          title: 'Test Login',
          username: 'user',
          password: 'pass',
          note: 'Some notes',
          websites: ['https://example.com'],
          customFields: []
        }
      }
    ])
    expect(addHttps).toHaveBeenCalledWith('example.com')
  })

  it('parses note row', () => {
    getRowsFromCsv.mockReturnValue([
      ['folder', 'favorite', 'type', 'name', 'notes'],
      ['', 'false', 'note', 'Note Title', 'Note content']
    ])
    const result = parseBitwardenCSV('csvText')
    expect(result[0]).toMatchObject({
      type: 'note',
      folder: '',
      isFavorite: false,
      data: {
        title: 'Note Title',
        note: 'Note content',
        customFields: []
      }
    })
  })

  it('parses custom type row', () => {
    getRowsFromCsv.mockReturnValue([
      ['folder', 'favorite', 'type', 'name'],
      ['Work', 'false', 'custom', 'Custom Entry']
    ])
    const result = parseBitwardenCSV('csvText')
    expect(result[0]).toMatchObject({
      type: 'custom',
      folder: 'Work',
      isFavorite: false,
      data: {
        title: 'Custom Entry',
        customFields: []
      }
    })
  })

  it('handles missing optional fields', () => {
    getRowsFromCsv.mockReturnValue([
      [
        'folder',
        'favorite',
        'type',
        'name',
        'login_username',
        'login_password',
        'login_uri'
      ],
      ['', '', 'login', 'No Folder', '', '', '', '']
    ])
    const result = parseBitwardenCSV('csvText')
    expect(result[0]).toMatchObject({
      type: 'login',
      folder: '',
      isFavorite: false,
      data: {
        title: 'No Folder',
        username: '',
        password: '',
        note: '',
        websites: [],
        customFields: []
      }
    })
  })

  it('extracts TOTP from CSV login_totp into otp field', () => {
    getRowsFromCsv.mockReturnValue([
      [
        'folder',
        'favorite',
        'type',
        'name',
        'notes',
        'login_username',
        'login_password',
        'login_uri',
        'login_totp',
        'fields'
      ],
      [
        '',
        'false',
        'login',
        'TOTP Login',
        '',
        'user',
        'pass',
        'example.com',
        'JBSWY3DPEHPK3PXP',
        ''
      ]
    ])
    const result = parseBitwardenCSV('csvText')
    expect(result[0].data.otp).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'TOTP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30
    })
    expect(result[0].data.customFields).toEqual([])
  })

  it('parses multiple websites', () => {
    getRowsFromCsv.mockReturnValue([
      [
        'folder',
        'favorite',
        'type',
        'name',
        'login_username',
        'login_password',
        'login_uri'
      ],
      ['', 'true', 'login', 'Multi', 'user', 'pass', 'site1.com,site2.com']
    ])
    const result = parseBitwardenCSV('csvText')
    expect(result[0].data.websites).toEqual([
      'https://site1.com',
      'https://site2.com'
    ])
    expect(addHttps).toHaveBeenCalledWith('site1.com')
    expect(addHttps).toHaveBeenCalledWith('site2.com')
  })
})

describe('parseBitwardenData', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('calls parseBitwardenJson for json fileType', () => {
    const json = JSON.stringify({
      items: [{ type: 2, name: 'Note' }]
    })
    const spy = jest.spyOn(JSON, 'parse')
    const result = parseBitwardenData(json, 'json')
    expect(spy).toHaveBeenCalledWith(json)
    expect(Array.isArray(result)).toBe(true)
    spy.mockRestore()
  })

  it('calls parseBitwardenCSV for csv fileType', () => {
    getRowsFromCsv.mockReturnValue([
      ['folder', 'favorite', 'type', 'name'],
      ['f', 'false', 'custom', 'n']
    ])
    const result = parseBitwardenData('csvText', 'csv')
    expect(result[0].type).toBe('custom')
  })

  it('throws error for unsupported fileType', () => {
    expect(() => parseBitwardenData('data', 'xml')).toThrow(
      'Unsupported file type'
    )
  })
})
