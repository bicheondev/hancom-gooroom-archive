# 사용자 작업: 한컴구름 3.3 정확 소스 흔적 수집

## 이 작업이 사용자에게 필요한 이유

자동 파이프라인은 다음 범위까지 완료했습니다.

- 참조 ISO의 크기와 SHA-256 검증
- `live/filesystem.squashfs` 추출
- 남은 7개 source/version의 설치 흔적과 패키지 changelog 확인
- 공개 Git 전체 이력에서 정확 버전 검색
- 참조 ISO에 보존된 Gooroom/Hancom `InRelease`의 source-index 해시 잠금
- 현행 저장소, HTTP/HTTPS, APT by-hash 및 공개 웹 아카이브 경로 탐색

참조 ISO에는 바이너리 `Packages` 인덱스와 설치 상태는 남아 있지만 정확한 `Sources`, `.dsc`, `.orig.tar.*`, `.debian.tar.*`는 들어 있지 않다. 따라서 자동 환경에서 접근할 수 없는 다음 위치만 사용자에게 맡긴다.

1. 과거 한컴구름 3.3 VM/PC의 APT 캐시
2. 2023년경 `update.hancomgooroom.com`에 접근 가능했던 네트워크
3. 과거 pbuilder/sbuild/개발 VM 또는 개인 소스 보관 디스크
4. 사용자에게 합법적으로 접근 권한이 있는 한컴·구름 소스 미러

계정, 토큰, VPN 비밀번호, SSH 키는 제출하지 않는다. 검증 도구가 만든 결과 ZIP만 제출한다.

## 남은 정확 source/version

```text
gnome-flashback             3.38.0-2+grm3u2+han3u4
gooroom-dockbarx-applet     0.3.1+grm3u1+han3u1
gooroom-guide               0.5.3+grm3u1+han3u1
gooroom-integration-applet  0.3.1+grm3u1+han3u3
gooroom-session-manager     0.3.9+grm3u1+han3u2
linux                       5.10.179-1+grm3u1
qtbase-opensource-src       5.15.2+dfsg-9+grm3u1
```

## 서명된 source-index 고정값

참조 ISO에 보존된 clearsigned `InRelease`가 다음 파일을 잠근다.

```text
Gooroom main/source/Sources.gz
size:   51094
sha256: 09e1abccac1bcd86a430318caab0f0c68224f42a567b8cee7bcf308ed7f4a166

Hancom main/source/Sources.gz
size:   7142
sha256: 5898f493b7ae9c750dbd11c80325bde5a3778357500d9acda24cc6e4e41c6a58
```

파일명이나 버전 문자열만 같은 것은 authority로 인정하지 않는다.

## 권장 실행 위치

우선순위는 다음과 같다.

1. 한컴구름 3.3을 실제로 사용했던 Linux VM 내부
2. 과거 한컴구름 빌드에 사용한 Debian/Ubuntu 빌드 VM
3. 옛 저장소가 열릴 가능성이 있는 사용자 네트워크
4. 소스 캐시가 있는 NAS·외장 디스크·다운로드 폴더

`.qcow2` 파일을 macOS 호스트에서 일반 파일처럼 검색하면 게스트 내부 APT 캐시는 보이지 않는다. 해당 VM을 부팅하고 게스트 내부에서 복구 도구를 실행한다.

## 최소 수동 명령

옛 저장소가 현재 네트워크에서 열리는지 확인할 때 사용할 수 있다.

```bash
mkdir -p hancom-gooroom-source-recovery
cd hancom-gooroom-source-recovery

curl -fL --retry 5 --connect-timeout 20 \
  -o gooroom-Sources.gz \
  http://update.hancomgooroom.com/gooroom/dists/gooroom-3.0/main/source/Sources.gz

curl -fL --retry 5 --connect-timeout 20 \
  -o hancom-Sources.gz \
  http://update.hancomgooroom.com/hancom/dists/hancom-3.0/main/source/Sources.gz

python3 - <<'PY'
from pathlib import Path
import hashlib

expected = {
    'gooroom-Sources.gz': (51094, '09e1abccac1bcd86a430318caab0f0c68224f42a567b8cee7bcf308ed7f4a166'),
    'hancom-Sources.gz': (7142, '5898f493b7ae9c750dbd11c80325bde5a3778357500d9acda24cc6e4e41c6a58'),
}
for name, (size, sha256) in expected.items():
    path = Path(name)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    print(name, path.stat().st_size, actual)
    if path.stat().st_size != size or actual != sha256:
        raise SystemExit(f'identity mismatch: {name}')
print('EXACT SOURCE INDICES VERIFIED')
PY
```

두 파일이 정확히 검증되면 그대로 대화에 첨부한다.

## 과거 Linux VM의 캐시 수집

전용 복구 키트를 우선 사용한다. 키트를 사용할 수 없는 경우 다음 명령으로 후보만 묶을 수 있다.

```bash
sudo find \
  /var/lib/apt/lists \
  /var/cache/apt \
  /var/cache/pbuilder \
  /var/cache/sbuild \
  /root /home \
  -type f \
  \( -iname '*source*Sources*' \
     -o -name '*.dsc' \
     -o -name '*.orig.tar.*' \
     -o -name '*.debian.tar.*' \
     -o -name '*.diff.gz' \
  \) -print0 2>/dev/null \
| sudo tar --null -T - -caf /tmp/hancom-gooroom-source-cache.tar.xz

sudo chown "$(id -u):$(id -g)" /tmp/hancom-gooroom-source-cache.tar.xz
```

이 방식은 후보 수집일 뿐이므로 자동 승격하지 않는다. 이후 파이프라인이 파일별 Source/Version, 크기, SHA-256을 다시 검증한다.

## 사용자 결과를 받은 뒤 자동으로 수행할 작업

1. 정확 `Sources` stanza에서 `Directory`와 source 구성 파일 잠금 추출
2. `.dsc` 및 모든 source member 획득
3. 크기·SHA-256·Source·Version 검증
4. `dpkg-source -x` 추출과 changelog 재검증
5. 네이티브 ARM64 빌드
6. DEB 버전·Architecture·AArch64 ELF 및 foreign ELF 0개 감사
7. rebuild result와 package pool 승격
8. source/build blocker 재계산
9. package layer가 완전히 닫힌 경우에만 ARM64 ISO 조립과 QEMU/UTM 부팅 감사
