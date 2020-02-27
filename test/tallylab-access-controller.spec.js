const assert = require('assert')
const naclFactory = require('js-nacl')
const TallyLabIAM = require('../index')
const OrbitDB = require('orbit-db')
const IPFS = require('ipfs')
const rmrf = require('rimraf')
const TallyLabIdentities = require('tallylab-orbitdb-identity-provider')

const IPFSConfig = { Addresses: { Swarm: [] }, Bootstrap: [] }

describe('Access Controller', function () {
  let iam, orbitdb, ipfs, identity, identities

  before(async () => {
    ipfs = await IPFS.create({ preload: { enabled: false }, config: IPFSConfig })

    iam = await new Promise((resolve, reject) => {
      naclFactory.instantiate((nacl) => {
        iam = new TallyLabIAM(nacl)
        identities = new TallyLabIdentities(nacl)
        resolve(iam)
      })
    })

    const seed = 'thisisexactlythirtytwocharacters'
    const tlKeys = identities.TallyLabIdentityProvider.keygen(seed)
    identity = await identities.Identities.createIdentity({
      type: 'TallyLab',
      id: tlKeys.signing.signPk.toString(),
      tlKeys
    })

    orbitdb = await OrbitDB.createInstance(ipfs, {
      AccessControllers: iam.AccessControllers,
      identity: identity
    })
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

    const randomKeys = identities.TallyLabIdentityProvider.keygen()
    const randomIdentity = await identities.Identities.createIdentity({
      type: 'TallyLab',
      id: randomKeys.signing.signPk.toString(),
      tlKeys: randomKeys,
      identityKeysPath: './randomkeys'
    })

    const orbitdb2 = await OrbitDB.createInstance(ipfs, {
      AccessControllers: iam.AccessControllers,
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
