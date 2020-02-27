/**
 * @module TallyLabIAM
 */

/**
 * @external orbit-db-access-controllers
 * @see https://github.com/orbitdb/orbit-db-access-controllers
 */

/**
 * @external orbit-db-identity-provider
 * @see https://github.com/orbitdb/orbit-db-identity-provider/
 */

/**
 * Note: We want to consider migration to the wasm-based
 * [libsodium.js](https://github.com/jedisct1/libsodium.js/)
 *
 * @external js-nacl
 * @see https://github.com/tonyg/js-nacl
 */

const AccessControllers = require('orbit-db-access-controllers')
const TallyLabAccessController = require('./src/tallylab-access-controller')

/**
 * This module exposes a single function as the entry point for TallyLabIAM. The function
 * takes a nacl instance (created via `nacl_factory.instantiate`) and returns an object containing
 * a {@link TallyLabIdentityProvider} object and a {@link TallyLabAccessController} object.
 *
 * Additionally, since linking to Orbit requires both usage and configuration of the
 * Orbit-internal AccessController and Identities object, this function handles the linking
 * and returns the aforementioned objects as well, in their modified state.
 *
 * @function TallyLabIAM
 * @see https://github.com/orbitdb/orbit-db-access-controllers#creating-a-custom-access-controller
 * @see https://github.com/orbitdb/orbit-db-identity-provider/#creating-an-identity
 *
 * @example
 * nacl_factory.instantiate((nacl) => {
 *   iam = new TallyLabIAM(nacl)
 * })
 *
 * @param {external:js-nacl} nacl output of `nacl_factory.instantiate`
 *
 * @returns {TallyLabAccess} See type definitions below
 */
function TallyLabAccess () {
  AccessControllers.addAccessController({ AccessController: TallyLabAccessController })

  return {
    TallyLabAccessController,
    AccessControllers
  }
}

/**
 * @typedef {Object} TallyLabAccess
 * @property {TallyLabAccessController} TallyLabAccessController - ACL Creation and Enforcement
 * @property {TallyLabIdentityProvider} TallyLabIdentityProvider - Identity via NACL keypairs
 * @property {external:orbit-db-identity-provider} Identities - Identities helper class from Orbit
 * @property {external:orbit-db-access-controllers} AccessControllers - AccessControllers helper class from Orbit
 */

module.exports = TallyLabAccess
