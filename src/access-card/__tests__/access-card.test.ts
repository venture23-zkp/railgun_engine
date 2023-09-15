import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import memdown from 'memdown';
import { AccessCardData, NoteAnnotationData, OutputType } from '../../models/formatted-types';
import { AccessCard } from '../access-card';
import WalletInfo from '../../wallet/wallet-info';
import { config } from '../../test/config.test';
import { Database } from '../../database/database';
import { RailgunWallet } from '../../wallet/railgun-wallet';

chai.use(chaiAsPromised);
const { expect } = chai;

const testMnemonic = config.mnemonic;
const testEncryptionKey = config.encryptionKey;

let db: Database;
let wallet: RailgunWallet;

describe('AccessCard', function run() {
  this.beforeAll(async () => {
    db = new Database(memdown());
    wallet = await RailgunWallet.fromMnemonic(
      db,
      testEncryptionKey,
      testMnemonic,
      0,
      undefined, // creationBlockNumbers
    );
    WalletInfo.setWalletSource('accessCardWallet');
  });

  it('Should encrypt and decrypt alphanumeric access card data', async () => {
    const sender = wallet.getViewingKeyPair();

    const accessCardData: AccessCardData = {
      name: 'Test Card',
      description: 'This is a sample description for AccessCard Test',
    };

    const encryptedAccessCardData = AccessCard.encryptCardInfo(accessCardData, sender.privateKey);

    expect(AccessCard.decryptCardInfo(encryptedAccessCardData, sender.privateKey)).to.deep.equal(
      accessCardData,
    );
  });

  it('Should encrypt and decrypt empty access card name and/or description', async () => {
    const sender = wallet.getViewingKeyPair();

    const accessCardData1: AccessCardData = {
      name: 'Test Card without description',
      description: '',
    };
    const accessCardData2: AccessCardData = {
      name: '',
      description: 'Test Card without name',
    };
    const accessCardData3: AccessCardData = {
      name: '',
      description: '',
    };

    const encryptedAccessCardData1 = AccessCard.encryptCardInfo(accessCardData1, sender.privateKey);
    const encryptedAccessCardData2 = AccessCard.encryptCardInfo(accessCardData2, sender.privateKey);
    const encryptedAccessCardData3 = AccessCard.encryptCardInfo(accessCardData3, sender.privateKey);

    expect(AccessCard.decryptCardInfo(encryptedAccessCardData1, sender.privateKey)).to.deep.equal(
      accessCardData1,
    );
    expect(AccessCard.decryptCardInfo(encryptedAccessCardData2, sender.privateKey)).to.deep.equal(
      accessCardData2,
    );
    expect(AccessCard.decryptCardInfo(encryptedAccessCardData3, sender.privateKey)).to.deep.equal(
      accessCardData3,
    );
  });

  it('Should encode and decode empty access card', async () => {
    expect(AccessCard.encodeAccessCardInfo(undefined)).to.equal('');
    expect(AccessCard.decodeAccessCardInfo('')).to.equal(undefined);
  });

  it('Should encode and decode long access card description', async () => {
    const accessCardData: AccessCardData = {
      name: 'name',
      description:
        'A really long memo with emojis 😐👩🏾‍🔧😎 and other text !@#$%^&*() Private memo field 🤡🙀🥰👩🏿‍🚒🧞 🤡 🙀 🥰 👩🏿‍🚒 🧞, in order to test a major memo for a real live production use case.',
    };

    const encoded = AccessCard.encodeAccessCardInfo(accessCardData);
    expect(encoded).to.deep.equal(
      '7b226e616d65223a226e616d65222c226465736372697074696f6e223a2241207265616c6c79206c6f6e67206d656d6f207769746820656d6f6a697320f09f9890f09f91a9f09f8fbee2808df09f94a7f09f988e20616e64206f7468657220746578742021402324255e262a28292050726976617465206d656d6f206669656c6420f09fa4a1f09f9980f09fa5b0f09f91a9f09f8fbfe2808df09f9a92f09fa79e20f09fa4a120f09f998020f09fa5b020f09f91a9f09f8fbfe2808df09f9a9220f09fa79e2c20696e206f7264657220746f20746573742061206d616a6f72206d656d6f20666f722061207265616c206c6976652070726f64756374696f6e2075736520636173652e227d',
    );

    const decoded = AccessCard.decodeAccessCardInfo(encoded);
    expect(decoded).to.deep.equal(accessCardData);
  });

  it('Should encode and decode access card description - new line over an emoji', async () => {
    const accessCardData = {
      name: 'Test name',
      description: `Private memo field 🙀🥰👩🏿‍🚒🧞 🤡 🙀 🥰 👩🏿‍🚒 🧞,
                    🤡`,
    };

    const encoded = AccessCard.encodeAccessCardInfo(accessCardData);
    expect(encoded).to.deep.equal(
      '7b226e616d65223a2254657374206e616d65222c226465736372697074696f6e223a2250726976617465206d656d6f206669656c6420f09f9980f09fa5b0f09f91a9f09f8fbfe2808df09f9a92f09fa79e20f09fa4a120f09f998020f09fa5b020f09f91a9f09f8fbfe2808df09f9a9220f09fa79e2c5c6e2020202020202020202020202020202020202020f09fa4a1227d',
    );

    const decoded = AccessCard.decodeAccessCardInfo(encoded);
    expect(decoded).to.deep.equal(accessCardData);
  });

  it('Should encode and decode access card without emojis', async () => {
    const accessCardData = {
      name: 'This is a really long name in order to test a major access for a real live production use case',
      description:
        'A really long access card in order to test a major access for a real live production use case.',
    };

    const encoded = AccessCard.encodeAccessCardInfo(accessCardData);
    const decoded = AccessCard.decodeAccessCardInfo(encoded);

    expect(decoded).to.deep.equal(accessCardData);
  });
});
