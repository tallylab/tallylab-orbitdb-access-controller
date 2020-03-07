const assert = require('assert')
const naclFactory = require('js-nacl')
const TallyLabAccess = require('../index')
const OrbitDB = require('orbit-db')
const IPFS = require('ipfs')
const rmrf = require('rimraf')
const TallyLabIdentities = require('tallylab-orbitdb-identity-provider')
const Keystore = require('orbit-db-keystore')

const IPFSConfig = { Addresses: { Swarm: [] }, Bootstrap: [] }

describe('Access Controller', function () {
  let orbitdb, ipfs, identity, identities, nacl, access, keystore

  before(async () => {
    ipfs = await IPFS.create({ preload: { enabled: false }, config: IPFSConfig })

    nacl = await new Promise((resolve, reject) => {
      naclFactory.instantiate((nacl) => {
        resolve(nacl)
      })
    })

    keystore = new Keystore()
    access = new TallyLabAccess()
    identities = new TallyLabIdentities()

    const seed = 'thisisexactlythirtytwocharacters'
    const tlKeys = identities.TallyLabIdentityProvider.keygen(nacl, seed)
    const id = tlKeys.signing.signPk.toString()
    const key = await keystore.getKey(id) || await keystore.createKey(id)
    const idSignature = await keystore.sign(key, id)
    const tlSignature = nacl.crypto_sign(idSignature, tlKeys.signing.signSk)

    identity = await identities.Identities.createIdentity({
      type: 'TallyLab',
      id: tlKeys.signing.signPk.toString(),
      tlSignature
    })

    orbitdb = await OrbitDB.createInstance(ipfs, {
      AccessControllers: access.AccessControllers,
      identity: identity
    })
  })

  beforeEach(async () => {
    await keystore.open()
  })

  after(async () => {
    await identity.provider._keystore.close()
    await identity.provider._signingKeystore.close()
    await orbitdb.disconnect()
    await ipfs.stop()

    const logError = (err) => err && console.error(err)

    rmrf('./orbitdb', logError)
    rmrf('./orbitdb2', logError)
    rmrf('./randomkeys', logError)
  })

  afterEach(async () => {
    await keystore.close()
  })

  it('creates a deterministic OrbitDB address', async () => {
    const db = await orbitdb.kvstore('root', {
      accessController: {
        type: 'tallylab',
        write: [identity.id]
      },
      replicate: false
    })
    await db.close()

    assert.strictEqual(db.address.root, 'zdpuAv6krzrir1i3b5SD74xtEsVate4SdZrQZTJ3CSfV2ADHg')
    const manifest = (await ipfs.dag.get(db.address.root)).value
    assert.deepStrictEqual(manifest, {
      name: 'root',
      type: 'keyvalue',
      accessController: '/ipfs/zdpuAzhfKhrPhb1VQZUAxE94m8P3Xomydf9yuJ512CH7nzdf4'
    })

    const accessController = (await ipfs.dag.get(manifest.accessController.split('/')[2])).value
    assert.deepStrictEqual(accessController, {
      params: {
        address: 'bafyreieved6ag5ci4jqeidr27nxxtdnunzhi45hrn7kl4wwekou5y7j3se'
      },
      type: 'tallylab'
    })

    const aclParams = (await ipfs.dag.get(accessController.params.address)).value
    assert.deepStrictEqual(aclParams, {
      name: 'root',
      type: 'tallylab',
      write: [identity.id]
    })
  })

  it('allows correct keys to write to the db', async () => {
    const db = await orbitdb.kvstore('root', {
      accessController: {
        type: 'tallylab',
        write: [identity.id]
      },
      replicate: false
    })

    await db.set('foo', 'bar')
    assert.deepStrictEqual(db.index, { foo: 'bar' })
    await db.close()
  })

  it('disallows incorrect keys to write to the db', async () => {
    const db = await orbitdb.kvstore('root', {
      accessController: {
        type: 'tallylab',
        write: [identity.id]
      },
      replicate: false
    })

    const randomKeys = identities.TallyLabIdentityProvider.keygen(nacl)
    const id = randomKeys.signing.signPk.toString()
    const key = await keystore.getKey(id) || await keystore.createKey(id)
    const idSignature = await keystore.sign(key, id)
    const tlSignature = nacl.crypto_sign(idSignature, randomKeys.signing.signSk)

    const randomIdentity = await identities.Identities.createIdentity({
      type: 'TallyLab',
      id: randomKeys.signing.signPk.toString(),
      tlSignature,
      identityKeysPath: './randomkeys'
    })

    const orbitdb2 = await OrbitDB.createInstance(ipfs, {
      AccessControllers: access.AccessControllers,
      identity: randomIdentity,
      directory: './orbitdb2'
    })
    const db2 = await orbitdb2.open(db.address.toString(), {
      accessController: {
        type: 'tallylab',
        write: [identity.id]
      },
      replicate: false
    })

    try {
      await db2.set('foo', 'baz')
    } catch (e) {
      await randomIdentity.provider._keystore.close()
      await identity.provider._signingKeystore.close()
      await orbitdb2.disconnect()
      assert(true)
    }
  })
})
