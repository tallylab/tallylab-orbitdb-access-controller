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
 * nacl_factory.instantiate(async (nacl) => {
 *   const IAM = new TallyLabIAM(nacl)
 *
 *   // Create an identity with the TallyLabIdentityProvider
 *   const identity = await IAM.Identities.createIdentity({
 *     type: 'TallyLab',
 *     id: tlKeys.signing.signPk.toString(),
 *     tlKeys,
 *     nacl
 *   })
 *
 *   const orbitdb = await OrbitDB.createInstance(ipfs, {
 *     AccessControllers: IAM.AccessControllers,
 *     identity: identity
 *   })
 *
 *   const rootDb = await orbitdb.kvstore('root', {
 *     accessController: {
 *       type: 'tallylab',
 *       write: [identity.id]
 *     }
 *   })
 * })
 * ```
 */
class TallyLabAccessController {
  /**
   * aasdsadsa d
   *
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
