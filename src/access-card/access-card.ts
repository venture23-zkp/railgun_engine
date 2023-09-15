import { arrayify, hexlify } from "../utils";
import { AccessCardData, EncryptedAccessCardData } from "../models";
import { aes, isDefined, isReactNative } from "../utils";


// todo: Is this needed?
// TextEncoder/TextDecoder (used in this file) needs to shimmed in React Native
if (isReactNative) {
  // eslint-disable-next-line global-require
  require('fast-text-encoding');
}

export class AccessCard {
  static decryptCardInfo(accessCardData: string, viewingPrivateKey: Uint8Array): Optional<AccessCardData> {
    if(!accessCardData || !accessCardData.length) {
      return undefined;
    }

    try {
      // remove 0x prefix
      const hexlified = hexlify(accessCardData);

      const metadataCipherText = {
        iv: hexlified.substring(0, 32),
        data: [hexlified.substring(32,)]
      };

      const decrypted = aes.ctr.decrypt(metadataCipherText, viewingPrivateKey);

      return AccessCard.decodeAccessCardInfo(decrypted[0]);
    } catch (err) {
      return undefined;
    }
  }

  static encryptCardInfo(accessCardInfo: AccessCardData, viewingPrivateKey: Uint8Array): EncryptedAccessCardData {
    const encodedAccessCard = AccessCard.encodeAccessCardInfo(accessCardInfo);

    const { iv, data } = aes.ctr.encrypt([encodedAccessCard], viewingPrivateKey);    
    
    return (iv + data[0]);
  }

  static encodeAccessCardInfo(accessCardInfo: Optional<AccessCardData>): string {
    if (!isDefined(accessCardInfo) || !isDefined(accessCardInfo.name) || !isDefined(accessCardInfo.description)) {
      return '';
    }
    const encoded = hexlify(new TextEncoder().encode(JSON.stringify(accessCardInfo)));
    return encoded;
  }

  static decodeAccessCardInfo(encoded: string): Optional<AccessCardData> {
    if (!encoded.length) {
      return undefined;
    }

    try {
      const decodedText = new TextDecoder().decode(Buffer.from(arrayify(encoded)));
      return JSON.parse(decodedText);
    } catch(err) {
      return undefined;
    }
  }
}