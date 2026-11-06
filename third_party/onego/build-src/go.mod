module github.com/chainreactors/onego/v2

go 1.24.0

toolchain go1.24.3

require (
	github.com/M09ic/go-ntlmssp v0.0.0-20230312133735-dcccd454dfe0
	github.com/chainreactors/fingers v1.2.2-0.20260714063144-070758342f45
	github.com/chainreactors/logs v0.0.0-20260624034259-9aaea4aa52cc
	github.com/chainreactors/neutron v0.1.1-0.20260714062907-716c6b167cb6
	github.com/chainreactors/proxyclient v1.1.1-0.20260714062913-bce898a8f790
	github.com/chainreactors/utils v0.0.0-20260711153742-f3d210a5fa9d
	github.com/jessevdk/go-flags v1.6.1
	github.com/panjf2000/ants/v2 v2.9.1
	golang.org/x/net v0.49.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/chainreactors/utils/parsers v0.0.3
	github.com/webview/webview_go v0.0.0-20240831120633-6173450d4dd6
)

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible // indirect
	github.com/facebookincubator/nvdtools v0.1.5 // indirect
	github.com/go-dedup/megophone v0.0.0-20170830025436-f01be21026f5 // indirect
	github.com/go-dedup/simhash v0.0.0-20170904020510-9ecaca7b509c // indirect
	github.com/go-dedup/text v0.0.0-20170907015346-8bb1b95e3cb7 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/mozillazg/go-pinyin v0.20.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	github.com/twmb/murmur3 v1.1.8 // indirect
	github.com/wasilibs/go-re2 v1.6.0 // indirect
	github.com/wasilibs/wazero-helpers v0.0.0-20250123031827-cd30c44769bb // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/text v0.31.0 // indirect
)

replace (
	github.com/chainreactors/utils/parsers => ./third_party/parsers
	github.com/jessevdk/go-flags => ./third_party/go-flags
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20191205180655-e7c4368fe9dd
	golang.org/x/net => golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200223170610-d5e6a3e2c0ae
	golang.org/x/text => golang.org/x/text v0.3.3
)

replace golang.org/x/sync => golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a

replace github.com/wasilibs/go-re2 => github.com/chainreactors/go-re2 v1.11.1-0.20260716152604-8121b6cd261e
