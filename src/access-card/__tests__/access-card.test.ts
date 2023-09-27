import chai from 'chai';
import memdown from 'memdown';
import { AccessCardData } from '../../models/formatted-types';
import { AccessCard } from '../access-card';
import WalletInfo from '../../wallet/wallet-info';
import { config } from '../../test/config.test';
import { Database } from '../../database/database';
import { RailgunWallet } from '../../wallet/railgun-wallet';

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
      name: 'n',
      description: 'd',
    };

    const encryptedAccessCardData = AccessCard.encryptCardInfo(accessCardData, sender.privateKey);

    expect(AccessCard.decryptCardInfo(encryptedAccessCardData, sender.privateKey)).to.deep.equal(
      accessCardData,
    );
  });

  it('Should encrypt and decrypt access card name and/or description as empty string', async () => {
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

  it('Should not encode and decode empty access card', async () => {
    expect(function () {
      AccessCard.encodeAccessCardInfo(undefined);
    }).to.throw('name and description are required');

    expect(AccessCard.decodeAccessCardInfo('')).to.equal(undefined);
  });

  it('Should not encode long access card description (>30bytes)', async () => {
    const accessCardData: AccessCardData = {
      name: 'name',
      description: 'A really long memo with a lot of information',
    };

    expect(function() {
      AccessCard.encodeAccessCardInfo(accessCardData);
    }).to.throw('Combined length of name and description can only be upto 30 bytes')
  });

  it('Should encode and decode access card description - new line over an emoji', async () => {
    const accessCardData = {
      name: '',
      description: `memo 🙀🧞🧞a,
      🤡`,
    };

    const encoded = AccessCard.encodeAccessCardInfo(accessCardData);
    expect(encoded).to.deep.equal(
      '30326d656d6f20f09f9980f09fa79ef09fa79e612c0a202020202020f09fa4a1',
    );

    const decoded = AccessCard.decodeAccessCardInfo(encoded);
    expect(decoded).to.deep.equal(accessCardData);
  });

  it('Should encode and decode access card upto 30 characters', async () => {
    const accessCardData = {
      name: 'Name',
      description:
        'A really long access card.',
    };

    const encoded = AccessCard.encodeAccessCardInfo(accessCardData);
    const decoded = AccessCard.decodeAccessCardInfo(encoded);

    expect(decoded).to.deep.equal(accessCardData);
  });
});
