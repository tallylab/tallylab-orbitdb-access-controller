# TallyLab's OrbitDB Access Controller

> TallyLab's OrbitDB plugins for Identity and Access Management

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Background](#background)
- [Security](#security)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [Future Work](#future-work)
- [License](#license)


## Background

Building distributed applications (dapps) without a centralized blockchain presents
significant difficulties with regard to keypair management: Storage, recovery, etc. Keypair
management, ulitimately, is a UX problem - a tradeoff between security and user convenience.

Other approaches are effective but do not make it easy on the users:
- Exporting and importing highly randomized keys
- Deterministic keys based on a strong password or passphrase

Both of the above approaches rely on one or both of the following:
- The user's own diligence in terms of saving their keys and recovering them, often utilizing
a third party service such as Keybase or a password manager that supports keypairs.
- The user's memory, having to recall a password or passphrase. Often times these are forgotten
or simply required to be stored in the same place as the keypair itself.

To mitigate these issues, TallyLab opted to use a variant of the second approach, using a
32 byte seed to generate keys via the nacl encryption library. However, in TL, the seed is
generated from highly personal, memory-based questions, similar to security questions.
Each question, while seemingly knowable, combines with the others to produce a set of
questions that would be very difficult for anybody else besides the primary user to know.

The answers are them summed together to create the 32 byte seed, and then passed into the
TallyLab Identity Provider to allow the user to "authenticate via memory" in a reliable way.

This package does **not** contain the aforementioned questions and instead handles everything
post-generation of the seed. Mainly, the two primary classes, TallyLabAccessController and
TallyLabIdentityProvider act as glue between TallyLab and the underlying OrbitDB infrastructure.

## Install

The primary focus for this package is browser usage. To generate the browser libraries:

```
$ git clone https://github.com/tallylab/tallylab-orbitdb-access-controller
$ make build
```

The final files will then be available in the `dist/` folder:

- `tallylab-orbitdb-access-controller.min.js` (minified)
- `tallylab-orbitdb-access-controller.min.js.map` (Source map for development purposes)

For a simple example, run `npm run example` and open your browser to the specified URL.

## Usage

This package exposes four items:
2. TallyLabAccessController
4. AccessControllers (helper class from OrbitDB not normally exposed)

It is used in TallyLab similarly to the following:

```JavaScript
nacl_factory.instantiate(async (nacl) => {
  const IAM = new TallyLabIAM(nacl)

  const tlKeys = IAM.TallyLabIdentityProvider.keygen('thisisexactlythirtytwocharacters')

  // Create an identity with the TallyLabIdentityProvider
  const identity = await IAM.Identities.createIdentity({
    type: 'TallyLab',
    id: tlKeys.signing.signPk.toString(),
    tlKeys
  })

  const orbitdb = await OrbitDB.createInstance(ipfs, {
    AccessControllers: IAM.AccessControllers,
    identity: identity
  })

  const rootDb = await orbitdb.kvstore('root', {
    accessController: {
      type: 'tallylab',
      write: [identity.id]
    }
  })
})
```

## Security

In order to test functionality, the automated tests intentionally expose the private signing
and encryption keys for the following seeds. Thus, these should be considered fully
compromised and should never be used for any users, ever.

- `thisisexactlythirtytwocharacters`
- `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
- `yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy`
- `zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz`

## Maintainers

- [@aphelionz](https://github.com/aphelionz)
- [@skybondsor](https://github.com/skybondsor)

## Contributing

Issues and PRs are welcome!

Development is streamlined through the `make watch` command which will watch files
and generate documentation, lint, and run automated tests via the `nodemon` module.

```
$ git clone https://bitbucket.org/tallylab/tallylab-orbitdb-iam
$ make watch
```

The `Makefile` also provides other useful commands for development such as:

```bash
$ make docs       # builds jsdoc for this repo with config in .jsdoc.config.js
$ make link       # lints js files using standard.js
$ make test       # runs automated tests once
$ make clean      # nukes node_modules and package-lock.json
$ make build      # builds browser files and stores them in /dist
$ make rebuild    # nukes node_modules and package-lock.json, and re-installs dependencies
```

## Future Work

- Access granting and revocation to external keys using OrbitDB instead of IPFS

## License

TBD © 2019 TallyLab, LLC
