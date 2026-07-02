# Changelog

## [0.5.2](https://github.com/michaelw/ext-authz-token-exchange/compare/v0.5.1...v0.5.2) (2026-07-02)


### Bug Fixes

* **deps:** update kubernetes monorepo to v0.36.2 ([#134](https://github.com/michaelw/ext-authz-token-exchange/issues/134)) ([d66fb4b](https://github.com/michaelw/ext-authz-token-exchange/commit/d66fb4be3bf54fcfb6c8792be91c3c2474cf8e6d))
* **deps:** update module github.com/coreos/go-oidc/v3 to v3.19.0 ([#141](https://github.com/michaelw/ext-authz-token-exchange/issues/141)) ([c1307fa](https://github.com/michaelw/ext-authz-token-exchange/commit/c1307fa42a104c867c7cdc19b2924879a956ddaa))
* **deps:** update module github.com/onsi/ginkgo/v2 to v2.31.0 ([#136](https://github.com/michaelw/ext-authz-token-exchange/issues/136)) ([c75c779](https://github.com/michaelw/ext-authz-token-exchange/commit/c75c7797c43a39f3cf67bdaa89aaa944e2617bdb))
* **deps:** update module github.com/onsi/ginkgo/v2 to v2.32.0 ([#144](https://github.com/michaelw/ext-authz-token-exchange/issues/144)) ([a9bec74](https://github.com/michaelw/ext-authz-token-exchange/commit/a9bec74eeb03b418d6a9334e8a60447b57443bc4))
* **deps:** update module github.com/onsi/gomega to v1.42.0 ([#137](https://github.com/michaelw/ext-authz-token-exchange/issues/137)) ([ca3b361](https://github.com/michaelw/ext-authz-token-exchange/commit/ca3b36152f626c72d38e1cc1117f713819499ea7))
* **deps:** update module github.com/onsi/gomega to v1.42.1 ([#146](https://github.com/michaelw/ext-authz-token-exchange/issues/146)) ([9120e12](https://github.com/michaelw/ext-authz-token-exchange/commit/9120e12ad7bd2764d5125cf0d6e0fe014443d394))
* **deps:** update module google.golang.org/grpc to v1.82.0 ([#155](https://github.com/michaelw/ext-authz-token-exchange/issues/155)) ([7ddc1ba](https://github.com/michaelw/ext-authz-token-exchange/commit/7ddc1ba5f00c3ef251d7e2a35e74dac440ad14a8))

## [0.5.1](https://github.com/michaelw/ext-authz-token-exchange/compare/v0.5.0...v0.5.1) (2026-06-12)


### Bug Fixes

* **deps:** update module github.com/onsi/ginkgo/v2 to v2.30.0 ([#133](https://github.com/michaelw/ext-authz-token-exchange/issues/133)) ([c9aca88](https://github.com/michaelw/ext-authz-token-exchange/commit/c9aca8817bca128451fbbc975087d611db475980))
* **deps:** update opentelemetry-go-contrib monorepo to v0.69.0 ([#107](https://github.com/michaelw/ext-authz-token-exchange/issues/107)) ([0e0f94f](https://github.com/michaelw/ext-authz-token-exchange/commit/0e0f94fe812635f43e787827c4130bac166d5af1))
* **devspace:** ignore nil starter-pack values ([#128](https://github.com/michaelw/ext-authz-token-exchange/issues/128)) ([69da433](https://github.com/michaelw/ext-authz-token-exchange/commit/69da43352e03bd4f3602402587f161d69bd3b400))
* **e2e:** default local keycloak route ([#129](https://github.com/michaelw/ext-authz-token-exchange/issues/129)) ([82ed719](https://github.com/michaelw/ext-authz-token-exchange/commit/82ed71972dc8abbde56a6cfa2a13361ecee1fe0f))
* **server:** preserve ext-proc raw header mutations ([00b810c](https://github.com/michaelw/ext-authz-token-exchange/commit/00b810cbafdef2b819147ecbaa4a702adb5cd62f))
* **server:** use string header values for authz mutations ([00b810c](https://github.com/michaelw/ext-authz-token-exchange/commit/00b810cbafdef2b819147ecbaa4a702adb5cd62f))

## [0.5.0](https://github.com/michaelw/ext-authz-token-exchange/compare/v0.4.1...v0.5.0) (2026-06-03)


### Features

* **plugin:** add GKE Service Extensions gateway mode ([7fbc829](https://github.com/michaelw/ext-authz-token-exchange/commit/7fbc82919159ebaed720366e82675804b6b11827))


### Bug Fixes

* **deps:** update opentelemetry-go monorepo to v1.44.0 ([#105](https://github.com/michaelw/ext-authz-token-exchange/issues/105)) ([4d94cdd](https://github.com/michaelw/ext-authz-token-exchange/commit/4d94cddb363f78f3e229a9dd343d38bfdee3313c))

## [0.4.1](https://github.com/michaelw/ext-authz-token-exchange/compare/v0.4.0...v0.4.1) (2026-05-19)


### Bug Fixes

* **deps:** update google.golang.org/genproto/googleapis/rpc digest to 037a81a ([#92](https://github.com/michaelw/ext-authz-token-exchange/issues/92)) ([c5a0344](https://github.com/michaelw/ext-authz-token-exchange/commit/c5a034448086dcbe75d99bacf4a92d734e3f0f00))
* **docker:** set build cache ownership ([01c3a11](https://github.com/michaelw/ext-authz-token-exchange/commit/01c3a11be0f2c4bbf85117c132021786a3495607))
* **docker:** set build cache ownership ([c5f0370](https://github.com/michaelw/ext-authz-token-exchange/commit/c5f03709d9a70938223bfdf85d5493473060c358))

## [0.4.0](https://github.com/michaelw/ext-authz-token-exchange/compare/v0.3.0...v0.4.0) (2026-05-18)


### Features

* **chart:** add Ext AuthZ Grafana dashboard ([573fa4c](https://github.com/michaelw/ext-authz-token-exchange/commit/573fa4cc0d2407f5dbbc113fc22b9526ba742a25))
* **chart:** add gateway authz observability wiring ([85141c4](https://github.com/michaelw/ext-authz-token-exchange/commit/85141c4a5e17b43d517ed2bb807fbc52883ebfd0))
* **exchange:** add named issuer profiles ([71e9477](https://github.com/michaelw/ext-authz-token-exchange/commit/71e94776d517110236357421881b245c0ff94aec))
* **observability:** add ext-authz RED metrics ([48abc1a](https://github.com/michaelw/ext-authz-token-exchange/commit/48abc1a681697606689379e543994b17fcae3bbd))


### Bug Fixes

* **deps:** update google.golang.org/genproto/googleapis/rpc digest to 3700d41 ([09a789e](https://github.com/michaelw/ext-authz-token-exchange/commit/09a789efb8ecaa4db36e64b8924bc8634f9e9446))
* **deps:** update google.golang.org/genproto/googleapis/rpc digest to 3700d41 ([e80d8cd](https://github.com/michaelw/ext-authz-token-exchange/commit/e80d8cd63994eb45b80d4ce198d3da5bb984f408))
* **deps:** update kubernetes monorepo to v0.36.1 ([76759a0](https://github.com/michaelw/ext-authz-token-exchange/commit/76759a0ebc2b4bb9bcc970dac857412e7191224c))
* **deps:** update kubernetes monorepo to v0.36.1 ([a053cb1](https://github.com/michaelw/ext-authz-token-exchange/commit/a053cb169267c2b34129271a66ab108244911cfe))
* **deps:** update module github.com/onsi/ginkgo/v2 to v2.29.0 ([da33da6](https://github.com/michaelw/ext-authz-token-exchange/commit/da33da6581ec251a148886cbfb76179f83f7b3c1))
* **deps:** update module github.com/onsi/ginkgo/v2 to v2.29.0 ([e28c641](https://github.com/michaelw/ext-authz-token-exchange/commit/e28c6417a495dbe5b5539c8e3d6cf51afc7349df))
* **deps:** update module github.com/onsi/ginkgo/v2 to v2.29.0 ([#87](https://github.com/michaelw/ext-authz-token-exchange/issues/87)) ([da33da6](https://github.com/michaelw/ext-authz-token-exchange/commit/da33da6581ec251a148886cbfb76179f83f7b3c1))
* **deps:** update module github.com/onsi/gomega to v1.41.0 ([f5df416](https://github.com/michaelw/ext-authz-token-exchange/commit/f5df4169978a226393d0130ee0b52a0415819292))
* **deps:** update module github.com/onsi/gomega to v1.41.0 ([491bb8a](https://github.com/michaelw/ext-authz-token-exchange/commit/491bb8a8221e11df214f35cd12122cc2101b11f7))
* **deps:** update module github.com/onsi/gomega to v1.41.0 ([#88](https://github.com/michaelw/ext-authz-token-exchange/issues/88)) ([f5df416](https://github.com/michaelw/ext-authz-token-exchange/commit/f5df4169978a226393d0130ee0b52a0415819292))
* **deps:** update module google.golang.org/grpc to v1.81.1 ([952a441](https://github.com/michaelw/ext-authz-token-exchange/commit/952a44138d9ac79d5182ab01b80af47a8c5dff99))
* **deps:** update module google.golang.org/grpc to v1.81.1 ([1f57c06](https://github.com/michaelw/ext-authz-token-exchange/commit/1f57c06b36b47616287a9c23611d3432ae293e2b))
* **deps:** update module google.golang.org/grpc to v1.81.1 ([#86](https://github.com/michaelw/ext-authz-token-exchange/issues/86)) ([952a441](https://github.com/michaelw/ext-authz-token-exchange/commit/952a44138d9ac79d5182ab01b80af47a8c5dff99))
* **renovate:** block indirect Go major bumps ([2bccea7](https://github.com/michaelw/ext-authz-token-exchange/commit/2bccea744c193d135376eb277a81a79fafae27ee))
* **renovate:** block indirect Go major bumps ([19408f8](https://github.com/michaelw/ext-authz-token-exchange/commit/19408f811e01a164a198dfbb0291700c757fe847))
* **renovate:** rebase automerged update PRs ([59fcfcb](https://github.com/michaelw/ext-authz-token-exchange/commit/59fcfcb13405394c8e98381c17fbad7d3c13e953))
* **tracing:** suppress health check spans ([ca5601b](https://github.com/michaelw/ext-authz-token-exchange/commit/ca5601bf6ed2c093e376383301fe7fbc970f9360))
* **tracing:** suppress health check spans ([ef8b816](https://github.com/michaelw/ext-authz-token-exchange/commit/ef8b81601a88c07bc538177aaaf1abec20332167))

## [0.3.0](https://github.com/michaelw/ext-authz-token-exchange/compare/v0.2.0...v0.3.0) (2026-05-08)


### Features

* add OpenTelemetry tracing tutorial ([292d15d](https://github.com/michaelw/ext-authz-token-exchange/commit/292d15db1f52ad9148abd074c940759c128a6b5c))
* **demo:** add explicit dashboard input token workflow ([2894908](https://github.com/michaelw/ext-authz-token-exchange/commit/2894908d44a8959619030747fde955648a0df935))
* **demo:** detect issuer scenarios for dashboard ([e398094](https://github.com/michaelw/ext-authz-token-exchange/commit/e39809451a233406f59cf7983f344e20f51c6165))
* **demo:** make scenario input tokens explicit ([9f8af6a](https://github.com/michaelw/ext-authz-token-exchange/commit/9f8af6a0a614a97c691d3206c89ea56fe62d4a2d))
* **demo:** verify dashboard input token signatures ([8958044](https://github.com/michaelw/ext-authz-token-exchange/commit/895804452d4d46fd823025848a9f7d6fabd24102))
* **e2e:** add keycloak token exchange profile ([489e87c](https://github.com/michaelw/ext-authz-token-exchange/commit/489e87c85e6fb2e7625d173113480943d6fdb8f0))
* **e2e:** add Keycloak token exchange profile ([6113d4f](https://github.com/michaelw/ext-authz-token-exchange/commit/6113d4ffb97e0f52a5203026fd34131b48388e4a))
* **e2e:** require explicit scenario behavior ([09d2aa7](https://github.com/michaelw/ext-authz-token-exchange/commit/09d2aa75fed1dafebdffd0154b6c7d0750620750))
* **tracing:** add OpenTelemetry token exchange spans ([ecd1e40](https://github.com/michaelw/ext-authz-token-exchange/commit/ecd1e40fc016c43c344dd85d722e2d9a205bc493))


### Bug Fixes

* **ci:** publish chart under ghcr charts namespace ([4f0f5ef](https://github.com/michaelw/ext-authz-token-exchange/commit/4f0f5efb9fe7a7af0a19d60cfaee2fd683d37218))
* **ci:** publish chart under ghcr charts namespace ([553804b](https://github.com/michaelw/ext-authz-token-exchange/commit/553804b8ab4d9de2a08845f7889661d29d98c01c))
* **dashboard:** align scenario inspector layout ([9cba98d](https://github.com/michaelw/ext-authz-token-exchange/commit/9cba98d8c8ffdaf5c6e15d546cfbe8b521c68dba))
* **dashboard:** clarify scenario and API status ([7335888](https://github.com/michaelw/ext-authz-token-exchange/commit/7335888d895faa08fda1c664d19af7c9274b01a2))
* **dashboard:** lazily fetch generated scenario tokens ([e736634](https://github.com/michaelw/ext-authz-token-exchange/commit/e736634f8681cb370c34836459714d05905fe019))
* **devspace:** self-hold local issuer profiles ([a6202c5](https://github.com/michaelw/ext-authz-token-exchange/commit/a6202c5d8312a563281ac8414096c7c41217846c))
* **renovate:** apply gomod tidy globally ([b9ac510](https://github.com/michaelw/ext-authz-token-exchange/commit/b9ac510be7bd4b23e2c0e2873275f8e7911d37ad))
* **renovate:** apply gomod tidy globally ([e211e1b](https://github.com/michaelw/ext-authz-token-exchange/commit/e211e1b2b2ffaf5c920daf66f7d5b5661996a77e))

## [0.2.0](https://github.com/michaelw/ext-authz-token-exchange/compare/v0.1.0...v0.2.0) (2026-05-07)


### Features

* **charts:** split plugin and demo helm releases ([130dd96](https://github.com/michaelw/ext-authz-token-exchange/commit/130dd9671e1c83febef50f836d7ea36591369606))
* **demo:** report live deployment status ([ab72cb5](https://github.com/michaelw/ext-authz-token-exchange/commit/ab72cb585bc44b523ae10c5048690b966aced086))
* **policy:** adopt nested match and exchange schema ([28be7a1](https://github.com/michaelw/ext-authz-token-exchange/commit/28be7a11f34a2e8ff592bfa4229d4a0c5ceb5736))


### Bug Fixes

* **chart:** use env for runtime configuration ([c4c3515](https://github.com/michaelw/ext-authz-token-exchange/commit/c4c351538088dd8d0c5618e69314d201c4d860a3))
* **chart:** use env for runtime configuration ([a835889](https://github.com/michaelw/ext-authz-token-exchange/commit/a8358897daf520610d64eecaf9e62d3b3079a330))
* **ci:** use app token for release please ([d3b444e](https://github.com/michaelw/ext-authz-token-exchange/commit/d3b444e79a3c07a31be5c6ef09ce79f36855956c))
* **ci:** use app token for release please ([a468b2e](https://github.com/michaelw/ext-authz-token-exchange/commit/a468b2e89ee87b5e3dc8e5e554a5dc7662baa328))
* **server:** clarify health check logging ([9cf2b4c](https://github.com/michaelw/ext-authz-token-exchange/commit/9cf2b4c74dfae3565fce5957d6ffde537ed0460b))
* **server:** clarify health check logging ([ae68013](https://github.com/michaelw/ext-authz-token-exchange/commit/ae6801336ca078241d44e94c87d5a670fb2c485f))
