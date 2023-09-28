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
      name: 'sample 1 name',
    };

    const encryptedAccessCardData = AccessCard.encryptCardInfo(accessCardData, sender.privateKey);

    expect(AccessCard.decryptCardInfo(encryptedAccessCardData, sender.privateKey)).to.deep.equal(
      accessCardData,
    );
  });

  it('Should encrypt and decrypt access card name as empty string', async () => {
    const sender = wallet.getViewingKeyPair();

    const accessCardData: AccessCardData = {
      name: '',
    };

    const encrypted = AccessCard.encryptCardInfo(accessCardData, sender.privateKey);
    
    expect(AccessCard.decryptCardInfo(encrypted, sender.privateKey)).to.deep.equal(
      accessCardData,
    );
  });

  it('Should not encode and decode empty access card', async () => {
    expect(function () {
      AccessCard.encodeAccessCardInfo(undefined);
    }).to.throw('name is required');

    expect(AccessCard.decodeAccessCardInfo('')).to.deep.equal({ name: ''});
  });

  it('Should not encode long access card (>16bytes)', async () => {
    const accessCardData: AccessCardData = {
      name: 'A really longName',
    };

    expect(function() {
      AccessCard.encodeAccessCardInfo(accessCardData);
    }).to.throw('name can only be upto 16 characters long')
  });

  it('Should encode and decode access card name - new line over an emoji', async () => {
    const accessCardData = {
      name: `🧞,
      🤡`
    };

    const encoded = AccessCard.encodeAccessCardInfo(accessCardData);
    expect(encoded).to.deep.equal(
      'f09fa79e2c0a202020202020f09fa4a1',
    );

    const decoded = AccessCard.decodeAccessCardInfo(encoded);
    expect(decoded).to.deep.equal(accessCardData);
  });

  it('Should encode and decode access card upto 16 characters', async () => {
    const accessCardData = {
      name: 'A valid nameData',
    };

    const encoded = AccessCard.encodeAccessCardInfo(accessCardData);
    const decoded = AccessCard.decodeAccessCardInfo(encoded);

    expect(decoded).to.deep.equal(accessCardData);
  });
});
