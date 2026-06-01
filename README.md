# pwndbg-tooling-overlays

`pwndbg` 전체 포크가 아니라, 실제로 추가/수정한 파일만 따로 모아둔 overlay 저장소다.

포함된 작업은 크게 두 축이다.

- 컨테이너 PID namespace 환경에서 `pwndbg`, `gdb-pwndbg`, `attach pwndbg chall` 진입 경로를 보정해 `heap` 분석이 더 잘 되도록 만든 변경
- QEMU 커널 디버깅에서 `kernel vmmap` 재계산 비용을 줄이기 위한 캐시 정책 추가

## 포함 내용

- `overlay/_system_overrides/`
  - 설치된 portable `pwndbg` wrapper를 덮어써서 `-p` / `-pid=` attach 시 `/proc/<pid>/root`를 자동 적용하는 스크립트
- `overlay/scripts/patch-installed-pwndbg.py`
  - 설치된 `pwndbg` / `gdb-pwndbg` / root `.gdbinit`를 자동 패치하는 도구
- `overlay/pwndbg/**`
  - 실제로 수정한 `pwndbg` 내부 파일만 포함
- `overlay/tests/**`
  - 관련 회귀 테스트 일부

## 적용 방식

이 저장소는 upstream `pwndbg` checkout 위에 덮어쓰는 방식으로 사용한다.

```bash
./apply-overlay.sh /path/to/pwndbg
```

그 후 필요하면 설치본 wrapper도 패치한다.

```bash
python3 overlay/scripts/patch-installed-pwndbg.py status
sudo python3 overlay/scripts/patch-installed-pwndbg.py apply
```

## 왜 별도 저장소로 분리했는가

기존 `pwndbg` 전체 소스 트리를 그대로 올리면 실제로 내가 건드린 부분이 희석된다.
이 저장소는 “내가 추가한 디버깅 툴링 개선”만 빠르게 보여주기 위한 용도다.
