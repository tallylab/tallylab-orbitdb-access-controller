const TallyLabIdentities = require('tallylab-orbitdb-identity-provider')

/**
 * > Manages write access to databases via TL keys. Also, by way of doing _that_, also
 * > guarantees that our db addresses are deterministic.
 *
 * An OrbitDB Access Controller is mostly a configuration entity, exposing simple
 * functions that regulate permisisons on a DB. Note that as a function of all entries
 * being on the global IPFS network, all databases are publicly readable.
 *
 * However, we can, and do protect writes access via the TallyLab signing keypair. This
 * is the job of the TallyLabAccessController - to verify write access to the database.
 *
 * Additionally, since:
 * 1. The keypairs are deterministically generated via a seed, and
 * 2. The address of the ACL is based on the keypair values, and
 * 3. The OrbitDB addresses rely on hash of the database name, type, and address of the ALC, then:
 *
 * TallyLab OrbitDB addresses will be deterministic, given a consistent database name and type.
 *
 * ## Usage:
 * ```JavaScript
 * // Requires js-nacl, tallylab-orbitdb-identity-provider, and orbit-db-keystore
 *
 * nacl_factory.instantiate(async (nacl) => {
 *   // Fire up IPFS vroom vroooom
 *   const ipfs = await Ipfs.create()
 *
 *   const tlIdentities = new TallyLabIdentities()
 *   console.log(tlIdentities)
 *
 *   const keystore = Keystore.create()
 *   await keystore.open()
 *
 *   // Generate keys, either with or without a seed
 *   const seed = 'thisisexactlythirtytwocharacters'
 *   const tlKeys = tlIdentities.TallyLabIdentityProvider.keygen(nacl, seed)
 *   console.log(tlKeys)
 *
 *   // Pre-sign with the keystore
 *   const id = tlKeys.signing.signPk.toString()
 *   const key = await keystore.getKey(id) || await keystore.createKey(id)
 *
 *   // Identities work on the basis of cross-signing the OrbitDB and your provided keys
 *   const idSignature = await keystore.sign(key, id)
 *   const tlSignature = nacl.crypto_sign(idSignature, tlKeys.signing.signSk)
 *
 *   // Create an identity with the TallyLabIdentityProvider
 *   const identity = await tlIdentities.Identities.createIdentity({
 *     type: 'TallyLab', id, keystore, tlSignature
 *   })
 *   console.log(identity)
 *
 *   console.log(await tlIdentities.TallyLabIdentityProvider.verifyIdentity(identity))
 *
 *   const access = new TallyLabAccess()
 *   const orbitdb = await OrbitDB.createInstance(ipfs, {
 *     AccessControllers: access.AccessControllers,
 *     identity: identity
 *   })
 *
 *   const db = await orbitdb.kvstore('root', {
 *     accessController: {
 *       type: 'tallylab',
 *       write: [identity.id]
 *     }
 *   })
 *
 *   // Will always equal /orbitdb/zdpuAv6krzrir1i3b5SD74xtEsVate4SdZrQZTJ3CSfV2ADHg/root
 *   console.log(db.id)
 *
 *   await db.put('foo', 'bar')
 *   console.log(db.index)
 *
 *   // Bad IDs can't write! Bad IDs!!
 *   const randomKeys = tlIdentities.TallyLabIdentityProvider.keygen(nacl)
 *   const id2 = randomKeys.signing.signPk.toString()
 *   const key2 = await keystore.getKey(id) || await keystore.createKey(id)
 *   const idSignature2 = await keystore.sign(key, id)
 *   const tlSignature2 = nacl.crypto_sign(idSignature, randomKeys.signing.signSk)
 *
 *   const randomIdentity = await tlIdentities.Identities.createIdentity({
 *     type: 'TallyLab',
 *     id: id2,
 *     tlSignature: tlSignature2,
 *     identityKeysPath: './randomkeys'
 *   })
 *
 *   const orbitdb2 = await OrbitDB.createInstance(ipfs, {
 *     AccessControllers: access.AccessControllers,
 *     identity: randomIdentity,
 *     directory: './orbitdb2'
 *   })
 *   const db2 = await orbitdb2.open(db.address.toString(), {
 *     accessController: {
 *       type: 'tallylab',
 *       write: [identity.id]
 *      },
 *     replicate: false
 *   })
 *
 *   // Throws an error
 *   await db2.set('foo', 'baz')
 * })
 * ```
 */
class TallyLabAccessController {
  /**
   * @constructor
   * @returns TallyLabAccessController
   */
  constructor (orbitdb, identities, options) {
    this._orbitdb = orbitdb
    this._options = options || {}
    this.idProvider = identities.TallyLabIdentityProvider
  }

  /**
   * Static type getter
   *
   * @returns string TallyLab
   */
  static get type () { return 'tallylab' }

  /**
   * Non-static type getter, passthrough to static
   *
   * @returns 'tallylab'
   */
  get type () {
    return this.constructor.type
  }

  /**
   * The main function of the TallyLabAccessController: Write Access.
   *
   * This method is used internally to OrbitDB and is generally never called directly.
   * However, it's helpful to know that the function checks four things:
   * 1. Does {@link TallyLabIdentityProvider#verifyIdentity} pass?
   * 2. Does the ID of the running OrbitDB node match the identity of the attempted entry?
   * 3. Does the `write` array inside the ACL contain the public key trying to write?
   * 4. Does the local keystore cache contain the public key trying to write?
   *
   * If any of the above fail, the write will be denied.
   *
   * @param {object} entry
   * @param {TallyLabIdentityProvider} identityProvider
   *
   * @returns Boolean can append / can not append
   */
  async canAppend (entry, identityProvider) {
    const orbitIdentity = this._orbitdb.identity
    const entryIdentity = entry.identity
    const verified = await this.idProvider.verifyIdentity(entryIdentity)

    if (!verified) return false
    if (orbitIdentity.id !== entryIdentity.id) return false
    if (this._options.write.indexOf(orbitIdentity.id) === -1) return false
    if (!(await identityProvider._keystore.hasKey(entryIdentity.id))) return false

    return true
  }

  /**
   * Factory method to statically create a new instance of the TallyLabAccessController.
   *
   * This method is used internally to OrbitDB and is generally never called directly.
   *
   * @returns TallyLabAccessController
   */
  static async create (orbitdb, options) {
    const identities = new TallyLabIdentities()
    return new TallyLabAccessController(orbitdb, identities, options)
  }

  /**
   * Reads ACL from IPFS via `ipfs.dag.get`
   *
   * @params {CID} A Content ID hash compatible with `ipfs.dag.get`
   * @returns {Object} JSON of the manifest details
   */
  async load (address) {
    const manifest = await this._orbitdb._ipfs.dag.get(address)
    return manifest.value
  }

  /**
   * Writes the ACL options to IPFS via `ipfs.dag.put`
   *
   * @returns {Object} JSON object `{ address: $HASH }`
   */
  async save () {
    const cid = await this._orbitdb._ipfs.dag.put(this._options)
    return { address: cid.toBaseEncodedString() }
  }
}

module.exports = TallyLabAccessController
