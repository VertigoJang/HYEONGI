# 출시 전 시험 (가상 머신 포함)

3.0.0을 내기 전에 아래 환경에서 설치와 기능을 확인합니다. 성능 측정(`benchmark/`)은 가상
머신에서 하면 숫자가 의미 없으므로, 여기서는 기능이 동작하는지만 봅니다.

| 환경 | 형태 | 시그니처 탐지기 | 집행 |
|---|---|---|---|
| RHEL 10.3 | 실제 컴퓨터 (확인 완료) | Snort 3 | XDP |
| Windows 11 | 실제 컴퓨터 | Suricata | Windows Defender 방화벽 |
| Windows 10 | VirtualBox | Suricata | Windows Defender 방화벽 |
| Debian | VirtualBox | Suricata | nftables, XDP(generic) |
| Arch | VirtualBox | Suricata 또는 Snort 3(AUR) | nftables, XDP(generic) |
| openSUSE | VirtualBox | Suricata | nftables, XDP(generic) |

## VirtualBox 설정

- **네트워크 어댑터 1: NAT.** 인터넷에 나가는 데 쓰고, 정상 트래픽 수집과 경보 시험도 이
  어댑터로 합니다. 인터페이스 이름은 보통 `enp0s3`이며, 설치 스크립트가 기본 경로를 보고
  자동으로 찾습니다.
- **공격 실습을 할 때만 어댑터 2: 내부 네트워크.** 칼리 같은 공격용 가상 머신과 같은 이름의
  내부 네트워크에 붙입니다. 이 네트워크는 집 네트워크와 분리되어 있습니다.
- **브리지 어댑터는 쓰지 않습니다.** 가상 머신이 집 네트워크에 그대로 올라가므로, 공격
  실습 트래픽이 집 네트워크로 나갈 수 있습니다.
- XDP는 `--mode generic`으로 시험합니다. 가상 랜카드의 native XDP 지원 여부는 확인하지
  않았습니다.
- 메모리는 4 GB 이상을 권합니다. LLM을 가상 머신 안에서 돌리려면 그보다 훨씬 많이 필요합니다.

## 가상 머신 없이 공격 실습: 네트워크 네임스페이스

공격용 가상 머신이 없어도 같은 컴퓨터 안에 격리된 공격자를 만들 수 있습니다.

```bash
sudo bash packaging/lab-netns.sh up          # hyatk(10.199.0.2) ⇄ hy-host(10.199.0.1)
sudo hyeongi demo on hy-host --model 모델파일
sudo ip netns exec hyatk nmap -n -sS -p 1-1000 10.199.0.1
sudo ip netns exec hyatk timeout 10 hping3 -S -p 80 -i u1000 10.199.0.1
sudo hyeongi demo off
sudo bash packaging/lab-netns.sh mode drop   # 피해자 응답 방식 전환 (rst|drop|reject)
sudo bash packaging/lab-netns.sh down
```

- 공격자 네임스페이스에는 기본 경로가 없어 10.199.0.1 말고는 아무 데도 닿지 않습니다.
- 네임스페이스 안에는 DNS가 없어서 nmap은 반드시 `-n`을 붙입니다. 빼면 이름 조회 단계에서 멈추거나 비정상 종료합니다.
- veth는 native XDP를 지원하므로 같은 링크에서 generic과 native를 비교할 수 있습니다.

## LLM(Ollama)

가상 머신마다 Ollama를 설치하지 않아도 시험은 됩니다. Ollama에 연결하지 못하면 자체 시험은
경고(`WARN`)만 내고, 검토 보고서에는 LLM 부분만 비고 "이 컴퓨터의 네트워크 장비와 겹치는
IP" 부분은 그대로 나옵니다.

LLM 부분까지 시험하려면 한 대(예: Windows 11 실제 컴퓨터)에서만 Ollama를 켜고 확인합니다.
다른 컴퓨터의 Ollama를 가상 머신에서 쓰려면 Ollama가 외부 연결을 받도록 바꿔야 하는데, 그러면
같은 네트워크의 다른 기기도 접속할 수 있게 되므로 시험이 끝나면 되돌립니다.

## 순서 (리눅스 가상 머신)

배포판별 패키지 이름은 `docs/linux.md`에 있습니다.

```bash
git clone https://github.com/VertigoJang/HYEONGI ~/hyeongi && cd ~/hyeongi
sudo bash packaging/install-capture.sh
sudo bash packaging/install-services.sh
# 시그니처 탐지기: 배포판의 Suricata를 설치하고 suricata.yaml의 interface를 맞춘 뒤
sudo suricata-update                      # 기본 규칙(ET Open) 받기
sudo systemctl enable --now suricata
sudo bash packaging/use-suricata.sh
# XDP까지 시험할 때
sudo bash packaging/install-xdp.sh --mode generic
sudo bash packaging/selftest.sh
```

## 순서 (윈도우)

`docs/windows.md`의 준비 단계(Python, Npcap, Suricata)를 마친 뒤 관리자 PowerShell에서
실행합니다.

```powershell
git clone https://github.com/VertigoJang/HYEONGI C:\hyeongi; cd C:\hyeongi
powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1
powershell -ExecutionPolicy Bypass -File packaging\windows\selftest.ps1
```

Windows 10은 2025년 10월 14일에 마이크로소프트의 일반 지원이 끝났습니다. 시험은 하지만,
문서에는 보안 업데이트를 받는 환경에서 쓰라고 적습니다.

## 자동 테스트

`tests/` 폴더의 테스트는 관리자 권한, 네트워크, bpftool 없이 돕니다. 바깥 명령(bpftool,
systemctl 등)을 모두 가짜로 바꿔 놓고, 코드가 그 답을 받았을 때 무엇을 하는지만 봅니다.
pytest가 필요합니다(Debian 계열 패키지 이름: `python3-pytest`).

```bash
python3 -m pytest -q tests
```

| 파일 | 보는 것 |
|---|---|
| `test_xdp_attach.py` | XDP 프로그램이 인터페이스에 붙어 있을 때만 차단을 기록하는지, 떨어졌으면 다시 붙이는지 |
| `test_block_retry.py` | 실패한 차단을 60초 뒤에 다시 시도하는지 |
| `test_net_status.py` | `hyeongi net`이 `enforce` 값과 감시 인터페이스를 사실대로 보여 주는지 |
| `test_practice_demo.py` | `practice end`가 수집 서비스를 되살리는지, 실습 모드 중 `demo on`을 거부하는지 |
| `conftest.py` | 가짜 bpftool과 그 응답 예시 |

패킷이 실제로 버려지는지는 이 테스트로 알 수 없습니다. 그 확인은 아래 자체 시험과 실습망에서
합니다.

## 자체 시험이 하는 일

`selftest.sh`와 `selftest.ps1`은 설정과 서비스를 읽기만 하고 바꾸지 않습니다. 예외는 차단
시험 하나입니다. 문서 예시용으로 예약된 주소 `203.0.113.250`(RFC 5737, 실제로 쓰는 곳이
없음)을 2분짜리 차단으로 넣었다가 바로 지웁니다.

| 항목 | 확인하는 것 |
|---|---|
| system | 배포판, 커널, Python 버전, 가상화 여부, 필수 패키지 |
| config | 설정 파일을 읽을 수 있는지, 설정된 인터페이스가 실제로 있는지 |
| services / tasks | `hyeongid`와 함께 설치한 서비스가 실행 중인지 |
| enforcement | 차단 목록에 넣고 지우는 과정이 실제로 되는지 |
| detection | 경보 형식을 읽을 수 있는지, 경보 파일이 쌓이는지 |
| capture | 학습용 수집 파일이 최근에 쓰였는지 |
| check | 이 컴퓨터의 DNS 서버와 게이트웨이를 읽을 수 있는지, Ollama에 연결되는지 |

`FAIL`이 0이면 통과입니다. `WARN`은 아직 경보가 없거나 Ollama가 없는 것처럼, 환경에 따라
생길 수 있는 상태입니다.

## 경보 시험

설치 직후에는 경보가 없어서 검토 단계를 확인할 수 없습니다. 널리 쓰이는 탐지 시험 주소에
접속하면 Suricata의 기본 규칙(ET Open)이 경보를 하나 냅니다.

```bash
curl -s http://testmynids.org/uid/index.html
sleep 5
sudo hyeongi report
```

보고서에 경보 1건과 함께 차단 대상 IP가 나오면 탐지, 차단 목록, 검토가 이어져 동작하는
것입니다. `enforce: false` 상태이므로 실제로 차단되지는 않습니다.
