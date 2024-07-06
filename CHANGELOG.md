# Changelog

## [0.6.1](https://github.com/bullfrogsec/bullfrog/compare/v0.6.0...v0.6.1) (2024-07-06)


### Bug Fixes

* Close file descriptors ([#52](https://github.com/bullfrogsec/bullfrog/issues/52)) ([13fe985](https://github.com/bullfrogsec/bullfrog/commit/13fe98528ceb3c2eff19a4983d89bc3e61131a82))
* Simplify Tetragon integration ([#55](https://github.com/bullfrogsec/bullfrog/issues/55)) ([7c3757b](https://github.com/bullfrogsec/bullfrog/commit/7c3757b03e3f98d577adddd7b6b9f2f5b018c73b))

## [0.6.0](https://github.com/bullfrogsec/bullfrog/compare/v0.5.5...v0.6.0) (2024-07-03)


### Features

* Prefix internal inputs with an underscore ([#49](https://github.com/bullfrogsec/bullfrog/issues/49)) ([c0f4e59](https://github.com/bullfrogsec/bullfrog/commit/c0f4e59dcab9ac92154f5e4c9a097fb1553af557))

## [0.5.5](https://github.com/bullfrogsec/bullfrog/compare/v0.5.4...v0.5.5) (2024-07-01)


### Bug Fixes

* filtering dns server in agent instead of nftables ([#45](https://github.com/bullfrogsec/bullfrog/issues/45)) ([e1a20a3](https://github.com/bullfrogsec/bullfrog/commit/e1a20a3e2a0c0641dff8ae34f92fb2e8acb722e9))
* only allow trusted local dns server ([#41](https://github.com/bullfrogsec/bullfrog/issues/41)) ([46f90f1](https://github.com/bullfrogsec/bullfrog/commit/46f90f18b7ee65240e346a60f0d0323002ab09aa))

## [0.5.4](https://github.com/bullfrogsec/bullfrog/compare/v0.5.3...v0.5.4) (2024-07-01)


### Bug Fixes

* Verify Tetragon SHA256 checksum ([#39](https://github.com/bullfrogsec/bullfrog/issues/39)) ([3b314cb](https://github.com/bullfrogsec/bullfrog/commit/3b314cb4acd3ada8f2d6fc9fbf2e64100509d3ec))

## [0.5.3](https://github.com/bullfrogsec/bullfrog/compare/v0.5.2...v0.5.3) (2024-06-28)


### Bug Fixes

* add pre-release in release workflow ([#32](https://github.com/bullfrogsec/bullfrog/issues/32)) ([6bbe61a](https://github.com/bullfrogsec/bullfrog/commit/6bbe61a073fb0eb168fd79ce5575e3b86f76bd5e))

## [0.5.2](https://github.com/bullfrogsec/bullfrog/compare/v0.5.1...v0.5.2) (2024-06-27)


### Bug Fixes

* use sudo to chmod agent ([#29](https://github.com/bullfrogsec/bullfrog/issues/29)) ([e6a8c1a](https://github.com/bullfrogsec/bullfrog/commit/e6a8c1a2ef6fe5b233781995e6e46c680e3dcc13))

## [0.5.1](https://github.com/bullfrogsec/bullfrog/compare/v0.5.0...v0.5.1) (2024-06-27)


### Bug Fixes

* fixing problem with agent installation ([#27](https://github.com/bullfrogsec/bullfrog/issues/27)) ([6287cf4](https://github.com/bullfrogsec/bullfrog/commit/6287cf455f993c8b4a1874eaf82520d7643b2f75))
* group annotations to avoid reaching limit ([#26](https://github.com/bullfrogsec/bullfrog/issues/26)) ([804f346](https://github.com/bullfrogsec/bullfrog/commit/804f346cfeebd7d234bbee61b2784501e164d00a))

## [0.5.0](https://github.com/bullfrogsec/bullfrog/compare/v0.4.1...v0.5.0) (2024-06-27)


### Features

* fetch agent from release and reliably wait for agent to be ready ([#18](https://github.com/bullfrogsec/bullfrog/issues/18)) ([98606c4](https://github.com/bullfrogsec/bullfrog/commit/98606c47408f749b09a1c2c65f9d46dbd4aa7a08))

## [0.4.1](https://github.com/bullfrogsec/bullfrog/compare/v0.4.0...v0.4.1) (2024-06-26)


### Bug Fixes

* allow dns in build step ([#11](https://github.com/bullfrogsec/bullfrog/issues/11)) ([0c7bc0e](https://github.com/bullfrogsec/bullfrog/commit/0c7bc0e45814594f0e965b03008816d3adfafde9))
* Dynamically allow domains from CNAME record + wait on agent ([#16](https://github.com/bullfrogsec/bullfrog/issues/16)) ([a241a67](https://github.com/bullfrogsec/bullfrog/commit/a241a6749ad41a69ddde1b16d80027509d1c9fce))
