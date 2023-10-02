import { arrayify, hexlify } from '../utils';
import { AccessCardData, EncryptedAccessCardData } from '../models';
import { aes, isDefined, isReactNative } from '../utils';

// TextEncoder/TextDecoder (used in this file) needs to shimmed in React Native
if (isReactNative) {
  // eslint-disable-next-line global-require
  require('fast-text-encoding');
}

/**
 * Use this class to encrypt/decrypt/encode/decode access card info.
 */
export class AccessCard {
  private static DELIMITER_LENGTH = 2;

  /**
   * Attempts to decrypt the encrypted access card info with the given private key
   * @param encryptedCardData encrypted access card `name` and `description`
   * @param viewingPrivateKey wallet viewing private key to decrypt with
   * @returns decrypted access card info on success. Returns undefined otherwise.
   */
  static decryptCardInfo(
    encryptedCardData: string,
    viewingPrivateKey: Uint8Array,
  ): Optional<AccessCardData> {
    if (!encryptedCardData || !encryptedCardData.length) {
      return undefined;
    }

    try {
      // remove 0x prefix
      const hexlified = hexlify(encryptedCardData);

      const metadataCipherText = {
        iv: hexlified.substring(0, 32),
        data: [hexlified.substring(32)],
      };

      const decrypted = aes.ctr.decrypt(metadataCipherText, viewingPrivateKey);

      return AccessCard.decodeAccessCardInfo(decrypted[0]);
    } catch (err) {
      return undefined;
    }
  }

  /**
   * Encrypt the given access card info with AES 256 encryption algorithm
   * @param `name` and `description` of access card
   * @param viewingPrivateKey wallet viewing private key to encrypt with
   * @returns encrypted access card data as string
   */
  static encryptCardInfo(
    accessCardInfo: AccessCardData,
    viewingPrivateKey: Uint8Array,
  ): EncryptedAccessCardData {
    const encodedAccessCard = AccessCard.encodeAccessCardInfo(accessCardInfo);

    const { iv, data } = aes.ctr.encrypt([encodedAccessCard], viewingPrivateKey);

    return iv + data[0];
  }

  /**
   * Encodes the given `name` and `description`
   * @param accessCardInfo `name` and `description` of access card
   * @returns encoded access card info
   */
  static encodeAccessCardInfo(accessCardInfo: Optional<AccessCardData>): string {
    if (
      !isDefined(accessCardInfo) ||
      !isDefined(accessCardInfo.name) ||
      !isDefined(accessCardInfo.description)
    ) {
      throw new Error('name and description are required');
    }

    const { name, description } = accessCardInfo;
    const dataToEncode = name + description;

    if (dataToEncode.length > 64) {
      throw new Error(
        'combined length of name and description should be less than or equal to 64 characters',
      );
    }

    const delimiterIndex = name.length; // delimiter for name & description
    const prefix = delimiterIndex.toString().padStart(this.DELIMITER_LENGTH, '0');

    const encoded = hexlify(new TextEncoder().encode(dataToEncode));

    return prefix + encoded;
  }
  /**
   * Attempts to decode the given encoded access card info
   * @param encoded encoded access card info
   * @returns `AccessCardData` on success. Returns `undefined` otherwise
   */
  static decodeAccessCardInfo(encoded: string): Optional<AccessCardData> {
    try {
      if (encoded.length === 0) {
        return undefined;
      }

      const delimiterIndex = Number(encoded.slice(0, this.DELIMITER_LENGTH));

      const decodedText = new TextDecoder().decode(
        Buffer.from(arrayify(encoded.slice(this.DELIMITER_LENGTH))),
      );

      const name = decodedText.slice(0, delimiterIndex);
      const description = decodedText.slice(delimiterIndex);
      return { name, description };
    } catch (err) {
      return undefined;
    }
  }
}
