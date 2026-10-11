# Gates: Creator Studio contract alignment patch

OWNS: GATES.md, README.md, configs/controller.yaml, docs/**, migrations/**, internal/api/**, internal/artifacts/**, internal/domain/**, internal/store/**, internal/workloads/**, cmd/controller/**, scripts/verify-creator-studio-contract.mjs

Scope: make the existing Creator Studio workload boundary precise and complete for immutable runnable implementations, async results, artifact lineage and compatibility, generic ingestion, stable blockers, and partial batch acceptance without exposing physical infrastructure controls

- [x] G0: this ledger states outcomes that can fail
  CHECK: node "C:\Users\Sasha\.codex\skills\unlazy\scripts\gate-lint.mjs" GATES.md
  EXPECT: LINT OK
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=E:\Anti Gravity\Load_Balancer_Plus; path=847f0fd540d7/63 entries; EXPECT=matched; output-sha256=497e1b1fd83aa8c97730b46891c668bfc53799ce4cdaa54b7d44728bf3aca6e2; output-bytes=150

- [x] G1: Creator capabilities expose only explicitly runnable implementation definitions with stable immutable identity, schemas, artifact contracts, and abstract locality while hiding hardware
  CHECK: set "GOTOOLCHAIN=local" && set "GOPROXY=off" && set "GOCACHE=%CD%\.cache\go-build-1.23.4" && set "GOMODCACHE=%CD%\.cache\gopath\pkg\mod" && ".cache\gopath\pkg\mod\golang.org\toolchain@v0.0.1-go1.23.4.windows-amd64\bin\go.exe" test ./internal/api ./internal/workloads -run "TestCreatorStudioCapabilities|TestRuntimeProfile" -count=1
  EXPECT: ok  	vram-governor/internal/workloads
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=E:\Anti Gravity\Load_Balancer_Plus; path=847f0fd540d7/63 entries; EXPECT=matched; output-sha256=bdc9d8b3cbeeefb1ea48608428b3a92cefcc6c23a5210bd7289a60bd3180c453; output-bytes=84

- [x] G2: output and uploaded artifacts preserve immutable producer and media provenance, and compatibility tokens survive storage lookup
  CHECK: set "GOTOOLCHAIN=local" && set "GOPROXY=off" && set "GOCACHE=%CD%\.cache\go-build-1.23.4" && set "GOMODCACHE=%CD%\.cache\gopath\pkg\mod" && ".cache\gopath\pkg\mod\golang.org\toolchain@v0.0.1-go1.23.4.windows-amd64\bin\go.exe" test ./internal/artifacts ./internal/api -run "TestArtifact|TestCreatorArtifact" -count=1
  EXPECT: ok  	vram-governor/internal/api
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=E:\Anti Gravity\Load_Balancer_Plus; path=847f0fd540d7/63 entries; EXPECT=matched; output-sha256=cb05718aae007ad85c5834c48d42e2696d5489d07cce2e1d88ff51dada78ed0c; output-bytes=84

- [x] G3: asynchronous local and hosted-style LLM workloads return the same retrievable artifact-backed public result and idempotent replay keeps that result
  CHECK: set "GOTOOLCHAIN=local" && set "GOPROXY=off" && set "GOCACHE=%CD%\.cache\go-build-1.23.4" && set "GOMODCACHE=%CD%\.cache\gopath\pkg\mod" && ".cache\gopath\pkg\mod\golang.org\toolchain@v0.0.1-go1.23.4.windows-amd64\bin\go.exe" test ./internal/api -run "TestCreatorAsyncLLM" -count=1
  EXPECT: ok  	vram-governor/internal/api
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=E:\Anti Gravity\Load_Balancer_Plus; path=847f0fd540d7/63 entries; EXPECT=matched; output-sha256=59eb46d60872384d04ca20e150cdb2f404c54140f49bb6c96ec069c2d761103d; output-bytes=39

- [x] G4: submission reports distinct capability, capacity, busy, deadline, route, approval, and source-compatibility reasons without adding public states
  CHECK: set "GOTOOLCHAIN=local" && set "GOPROXY=off" && set "GOCACHE=%CD%\.cache\go-build-1.23.4" && set "GOMODCACHE=%CD%\.cache\gopath\pkg\mod" && ".cache\gopath\pkg\mod\golang.org\toolchain@v0.0.1-go1.23.4.windows-amd64\bin\go.exe" test ./internal/api -run "TestCreatorBlockingReasons|TestCreatorArtifactCompatibility" -count=1
  EXPECT: ok  	vram-governor/internal/api
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=E:\Anti Gravity\Load_Balancer_Plus; path=847f0fd540d7/63 entries; EXPECT=matched; output-sha256=0681f66c01761378f99ff77eea7693cd3be4e9399313f28393fde33775ac87b1; output-bytes=39

- [x] G5: batch submission precisely reports every accepted and rejected item and retrying accepted identities cannot duplicate workloads
  CHECK: set "GOTOOLCHAIN=local" && set "GOPROXY=off" && set "GOCACHE=%CD%\.cache\go-build-1.23.4" && set "GOMODCACHE=%CD%\.cache\gopath\pkg\mod" && ".cache\gopath\pkg\mod\golang.org\toolchain@v0.0.1-go1.23.4.windows-amd64\bin\go.exe" test ./internal/api -run "TestCreatorBatchPartialAcceptance" -count=1
  EXPECT: ok  	vram-governor/internal/api
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=E:\Anti Gravity\Load_Balancer_Plus; path=847f0fd540d7/63 entries; EXPECT=matched; output-sha256=12fb91797a119699c8d3f631e4d7bf0fac6f1c73a389843191633e494ff9322d; output-bytes=39

- [x] G6: working-set correctness and logical retry fencing behavior remain unchanged by the contract extensions
  CHECK: set "GOTOOLCHAIN=local" && set "GOPROXY=off" && set "GOCACHE=%CD%\.cache\go-build-1.23.4" && set "GOMODCACHE=%CD%\.cache\gopath\pkg\mod" && ".cache\gopath\pkg\mod\golang.org\toolchain@v0.0.1-go1.23.4.windows-amd64\bin\go.exe" test ./internal/api ./internal/workloads -run "TestCreatorStudioWorkingSet|TestCreatorStudioWorkloads|TestNodeLoss" -count=1
  EXPECT: ok  	vram-governor/internal/workloads
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=E:\Anti Gravity\Load_Balancer_Plus; path=847f0fd540d7/63 entries; EXPECT=matched; output-sha256=c9c4620f70c9bcb881f029eeac99393fee7487c59a313bd639341afde5fb564c; output-bytes=84

- [x] G7: documentation and source describe the implemented Creator boundary and contain every required contract section
  CHECK: node scripts/verify-creator-studio-contract.mjs
  EXPECT: Creator Studio contract verification passed
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=E:\Anti Gravity\Load_Balancer_Plus; path=847f0fd540d7/63 entries; EXPECT=matched; output-sha256=a21ffe49b00b14218549bd697b326db3ea9e55529346e780c5b078228925a2f6; output-bytes=44

- [x] G8: the complete Go regression suite passes offline with the repository-cached toolchain and dependencies
  CHECK: set "GOTOOLCHAIN=local" && set "GOPROXY=off" && set "GOCACHE=%CD%\.cache\go-build-1.23.4" && set "GOMODCACHE=%CD%\.cache\gopath\pkg\mod" && ".cache\gopath\pkg\mod\golang.org\toolchain@v0.0.1-go1.23.4.windows-amd64\bin\go.exe" test ./...
  EXPECT: ok  	vram-governor/internal/workloads
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=E:\Anti Gravity\Load_Balancer_Plus; path=847f0fd540d7/63 entries; EXPECT=matched; output-sha256=a0a070cee7441943a9d1e33cfb33753e9edcd6bf160f5a479209182d072e2b11; output-bytes=776

- [x] G9: final reconciliation confirms every requested deliverable is implemented, verified, or explicitly reported as a remaining gap
  EVIDENCE: Re-read contract clauses 1-30 and deliverables A-I against routes, schemas, stores, migrations, tests, and integration docs on 2026-09-01; live PostgreSQL application, real media workflow execution, hosted credentials, cross-adapter acceptable sets, and unavailable Windows race instrumentation are explicitly retained for the final gap report.
