/**
 * @module TallyLabIAM
 */

/**
 * @external orbit-db-access-controllers
 * @see https://github.com/orbitdb/orbit-db-access-controllers
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
 * This module exposes a single function as the entry point for TallyLabIAccess. The function
 * returns an object containing a {@link TallyLabAccess} object.
 *
 * Additionally, since linking to Orbit requires both usage and configuration of the
 * Orbit-internal AccessController object, this function handles the linking
 * and returns the aforementioned objects as well, in their modified state.
 *
 * @function TallyLabAccess
 * @see https://github.com/orbitdb/orbit-db-access-controllers#creating-a-custom-access-controller
 * @see https://github.com/orbitdb/orbit-db-identity-provider/#creating-an-identity
 *
 * @example
 * const access = new TallyLabAccess(nacl)
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
 * @property {external:orbit-db-access-controllers} AccessControllers - AccessControllers helper class from Orbit
 */

module.exports = TallyLabAccess
