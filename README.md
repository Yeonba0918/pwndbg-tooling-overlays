# Pwndbg Debugging Workflow Improvements

`pwndbg`를 그대로 포크해서 전체 코드를 보여주기보다, 실제로 내가 추가한 디버깅 워크플로우 개선만 분리한 프로젝트다.

이 프로젝트는 세 가지 실제 불편함에서 시작했다.

- Docker / PID namespace 환경에서 `attach pwndbg chall` 또는 `pwndbg -p <pid>`로 붙으면 `heap` 분석이 자주 깨졌다.
- QEMU Linux kernel 디버깅에서는 `vmmap` 계산 비용 때문에 stop 이후 응답이 느려지는 경우가 있었다.
- exploit 단계 사이에서 `heap`, `bins`, `malloc-chunk` 결과를 손으로 비교하는 과정이 번거로웠다.

## What This Project Solves

### 1. Container-aware heap debugging

컨테이너 내부 프로세스에 attach할 때 아래 같은 문제가 자주 발생한다.

- `target:/...` 경로 때문에 shared library를 host에서 찾지 못함
- `libthread_db`를 host glibc 기준으로 잘못 찾음
- stripped libc 환경에서 `heap` 명령이 바로 실패하거나 수동 설정을 요구함

이 프로젝트는 attach 진입점에서 `/proc/<pid>/root`를 이용해 컨테이너 rootfs를 자동 반영하도록 구성한다.

- 실행 파일 경로를 `/proc/<pid>/root/...` 기준으로 재지정
- `sysroot`, `solib-search-path`, `libthread-db-search-path`, `debug-file-directory` 자동 적용
- `gdb-pwndbg`와 portable `pwndbg`의 attach 경로 일관화
- 심볼이 없는 경우에도 기존 heuristic heap resolver가 바로 동작하도록 유도

결과적으로 실제 heap pwn challenge 환경에서 `heap` 명령이 수동 주소 입력 없이 바로 동작하도록 개선했다.

### 2. Faster kernel vmmap handling

QEMU kernel debugging에서는 `kernel vmmap` 재계산이 stop마다 반복되면 체감이 크게 느려질 수 있다.

이 프로젝트는 커널 vmmap 캐시 정책을 추가했다.

- `kernel-vmmap-cache = auto | per-stop | persistent`
- 일반 커널 디버깅에서는 결과를 더 오래 재사용
- `kcurrent --set`으로 task-specific PGD가 바뀌면 캐시 자동 무효화

즉, 정확도를 유지하면서도 page table / monitor 기반 vmmap 재계산 비용을 줄이는 방향이다.

### 3. Heap snapshot / diff workflow

힙 익스플로잇을 진행할 때는 “한 단계 전과 지금이 어떻게 달라졌는지”를 빠르게 보는 게 중요하다.

이 프로젝트는 이를 위해 다음 흐름을 추가한다.

- `heap-snapshot [name]`
- `heap-snapshots`
- `heap-diff [before] [after]`

스냅샷에는 현재 arena 기준 chunk 상태와 bin 체인이 저장되고, diff에서는 메타데이터 변화, chunk 추가/삭제/필드 변경, bin 체인 변화를 요약해 보여준다.

## Repository Structure

이 저장소는 upstream `pwndbg` 전체를 포함하지 않는다.
실제로 수정한 부분만 overlay 형태로 담고 있다.

- `overlay/pwndbg/**`
  - 수정한 `pwndbg` 내부 파일
- `overlay/_system_overrides/`
  - 설치된 portable `pwndbg` / `gdb-pwndbg` wrapper 교체용 스크립트
- `overlay/scripts/patch-installed-pwndbg.py`
  - 설치된 환경에 자동 적용하는 패치 도구
- `overlay/tests/**`
  - 관련 회귀 테스트 일부
- `apply-overlay.sh`
  - 기존 `pwndbg` checkout 위에 overlay를 덮어쓰는 도구

## Apply To a Local Pwndbg Checkout

```bash
./apply-overlay.sh /path/to/pwndbg
```

그 후 설치된 portable `pwndbg` wrapper까지 손보려면:

```bash
python3 overlay/scripts/patch-installed-pwndbg.py status
sudo python3 overlay/scripts/patch-installed-pwndbg.py apply
```

## Why This Repo Exists

처음에는 `pwndbg` 전체 소스 트리를 그대로 올렸지만, 그렇게 하면 실제로 내가 건드린 부분이 묻힌다.

이 저장소는:

- 어떤 문제를 해결하려고 했는지
- 정확히 어떤 파일을 바꿨는지
- 그 변경이 실제 디버깅 경험을 어떻게 바꿨는지

를 더 명확하게 보여주기 위해 따로 분리한 프로젝트 저장소다.
