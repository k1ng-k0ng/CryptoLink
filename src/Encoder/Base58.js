
import ByteEncoder from '../ByteEncoder'
import Encoder from '../Encoder'
import StringUtil from '../StringUtil'
import {
  encode as b58encode,
  decode as b58decode
} from './Hash/baseN.js';

const meta = {
  name: 'base58',
  title: 'Base58',
  category: 'Encoding',
  type: 'encoder'
}


/**
 * The default Base58 base alphabet
 * @type {string}
 */
const defaultAlphabet =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/**
 * Array of Base58 variant options extending the default options.
 * @type {object[]}
 */
const variants = [
  {
    name: 'base58',
    label: 'Base58',
    description: null,
    alphabet: `${defaultAlphabet}`
  },
  {
    name: 'custom',
    label: 'Custom'
  }
]

/**
 * Encoder brick for base58 encoding and decoding
 */
export default class Base58Encoder extends Encoder {
  /**
   * Returns brick meta.
   * @return {object}
   */
  static getMeta () {
    return meta
  }

  /**
   * Constructor
   */
  constructor () {
    super()
    this.addSettings([
      {
        name: 'variant',
        type: 'enum',
        value: variants[0].name,
        elements: variants.map(variant => variant.name),
        labels: variants.map(variant => variant.label),
        descriptions: variants.map(variant => variant.description),
        randomizable: false
      },
      {
        name: 'alphabet',
        type: 'text',
        value: variants[0].alphabet,
        uniqueChars: true,
        minLength: 64,
        maxLength: 64,
        caseSensitivity: true,
        visible: false
      },
      {
        name: 'padding',
        type: 'text',
        value: '=',
        blacklistChars: variants[0].alphabet,
        minLength: 1,
        maxLength: 1,
        randomizable: false,
        visible: false,
        width: 6
      },
      {
        name: 'paddingOptional',
        type: 'boolean',
        value: false,
        randomizable: false,
        visible: false,
        width: 6
      }
    ])
  }

  /**
   * Performs encode on given content.
   * @protected
   * @param {Chain} content
   * @return {number[]|string|Uint8Array|Chain} Encoded content
   */
  performEncode (content) {
    // Forward request to the internal byte encoder
    return b58encode(content.getBytes(), defaultAlphabet);

    // return ByteEncoder.base64StringFromBytes(
    //   content.getBytes(),
    //   this.getVariantOptions())
  }

  /**
   * Performs decode on given content.
   * @protected
   * @param {Chain} content
   * @return {number[]|string|Uint8Array|Chain} Decoded content
   */
  performDecode (content) {    
    // Forward request to the internal byte encoder
    return b58decode(content.getString(), defaultAlphabet);
    // return ByteEncoder.bytesFromBase64String(
    //   content.getString(),
    //   this.getVariantOptions())
  }

  /**
   * Triggered when a setting field has changed.
   * @protected
   * @param {Field} setting Sender setting field
   * @param {mixed} value New field value
   */
  settingValueDidChange (setting, value) {
    switch (setting.getName()) {
      case 'variant': {
        // Make alphabet and padding settings available with the custom variant
        this.getSetting('alphabet').setVisible(value === 'custom')
        this.getSetting('padding').setVisible(value === 'custom')
        this.getSetting('paddingOptional').setVisible(value === 'custom')
        break
      }

      case 'alphabet': {
        // Alphabet characters are not allowed to be used as padding
        this.getSetting('padding').setBlacklistChars(value)
        break
      }
    }
  }

  /**
   * Returns the current variant options.
   * @return {object} Variant options
   */
  getVariantOptions () {
    const name = this.getSettingValue('variant')
    if (name === 'custom') {
      // Compose custom options
      return {
        alphabet: this.getSettingValue('alphabet').getString(),
        padding: this.getSettingValue('padding').getCharAt(0),
        paddingOptional: this.getSettingValue('paddingOptional')
      }
    }

    // Find variant options
    return variants.find(variant => variant.name === name)
  }
}
