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
  /**
   * Attempts to decrypt the encrypted access card info with the given private key
   * @param encryptedCardData encrypted access card `name`
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
   * @param accessCardInfo `name` of access card
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
   * Encodes the given `name` 
   * @param accessCardInfo `name` and of access card
   * @returns encoded access card info
   */
  static encodeAccessCardInfo(accessCardInfo: Optional<AccessCardData>): string {
    if (
      !isDefined(accessCardInfo) ||
      !isDefined(accessCardInfo.name)
    ) {
      throw new Error('name is required');
    }

    const { name } = accessCardInfo;

    const encoded = hexlify(new TextEncoder().encode(name));

    // encoded data should be less than or equal to 16bytes
    if (encoded.length > 32) {
      throw new Error('name can only be upto 16 characters long');
    }

    return encoded;
  }
  /**
   * Attempts to decode the given encoded access card info
   * @param encoded encoded access card info
   * @returns `AccessCardData` on success. Returns `undefined` otherwise
   */
  static decodeAccessCardInfo(encoded: string): Optional<AccessCardData> {
    try {
      const decodedText = new TextDecoder().decode(
        Buffer.from(arrayify(encoded)),
      );

      return { name: decodedText };
    } catch (err) {
      return undefined;
    }
  }
}
