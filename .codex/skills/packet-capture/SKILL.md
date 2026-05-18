---
name: packet-capture
description: Capture and inspect packets in containerized network labs with docker exec, tcpdump, pcap files, async capture sessions, and Wireshark streaming. Use when Codex needs to do packet capture, パケットキャプチャ, tcpdump, pcap capture, live Wireshark viewing, inspect packets on a device/interface, verify ping/BGP/ARP/connectivity traffic, or start tcpdump in one session and review it after generating traffic.
---

# Packet Capture

## Core Workflow

Use `tcpdump` from inside the target container network namespace. Prefer `docker exec -it` for human-readable, terminal-rendered commands, especially network OS containers. Use `docker exec -i` when streaming binary pcap data to stdout.

1. Identify the target node and interface:

```bash
docker exec -it <node> ip -br link
docker exec -it <node> ip -br addr
```

2. Start `tcpdump` on the device/interface before generating traffic:

```bash
docker exec -it <node> tcpdump -l -nn -i <interface> <filter>
```

Examples:

```bash
docker exec -it dc1-leaf1 tcpdump -l -nn -i e1-1 icmp
docker exec -it dc1-spine1 tcpdump -l -nn -i e1-49 tcp port 179
docker exec -it dc1-leaf1 tcpdump -l -nn -e -vvv -i e1-1 arp or icmp
```

3. Generate traffic from another container/session:

```bash
docker exec -it dc1-client1 ping -I 10.201.1.11 -c 5 -W 1 10.201.1.1
```

4. Interpret the packet direction and source/destination. For a successful 5-count ping, expect 10 ICMP packets:

```text
IP 10.201.1.11 > 10.201.1.1: ICMP echo request
IP 10.201.1.1 > 10.201.1.11: ICMP echo reply
```

Use `-c 10` to stop automatically after five request/reply pairs:

```bash
docker exec -it <node> tcpdump -l -nn -i <interface> -c 10 icmp
```

## Async Sessions

When using Codex tools, start the long-running `tcpdump` command first with a TTY and short yield. Keep the returned session ID, run the traffic-generation command separately, then poll or stop the tcpdump session.

Pattern:

```text
1. exec_command: docker exec -it <node> tcpdump -l -nn -i <interface> <filter>
   - set tty=true
   - keep the session_id

2. exec_command: docker exec -it <source> ping ...

3. write_stdin(session_id, chars="")
   - read captured output

4. write_stdin(session_id, chars="\u0003")
   - send Ctrl-C if tcpdump is still running
```

For users doing this manually, explain it as two terminal windows:

```bash
# terminal A
docker exec -it dc1-leaf1 tcpdump -l -nn -i e1-1 icmp

# terminal B
docker exec -it dc1-client1 ping -I 10.201.1.11 -c 5 -W 1 10.201.1.1
```

## Capture Pcap

Write pcap inside the container, then copy it to the host:

```bash
docker exec -it <node> tcpdump -nn -i <interface> -c <packet-count> -w /tmp/capture.pcap <filter>
docker cp <node>:/tmp/capture.pcap ./capture.pcap
```

If a previous file causes permission problems, remove it first:

```bash
docker exec <node> rm -f /tmp/capture.pcap
```

Validate the pcap from the container or host with:

```bash
docker exec <node> tcpdump -nn -r /tmp/capture.pcap
tcpdump -nn -r ./capture.pcap
```

## Wireshark For Users

When the user wants to watch packets live from the Mac host, show the repo script explicitly:

```bash
./wireshark-docker.sh <container> <interface> [tcpdump-filter...]
```

Examples:

```bash
./wireshark-docker.sh dc1-leaf1 e1-1
./wireshark-docker.sh dc1-leaf1 e1-1 icmp
./wireshark-docker.sh dc1-spine1 e1-49 tcp port 179
```

This script streams pcap from Docker to Wireshark:

```bash
docker exec -i <container> tcpdump -U -s 0 -ni <interface> -w - <filter> \
  | /Applications/Wireshark.app/Contents/MacOS/Wireshark -k -i -
```

Use `docker exec -i`, not `-it`, for Wireshark streaming because pcap is binary stdout. If Wireshark is installed somewhere else, show:

```bash
WIRESHARK=/path/to/Wireshark ./wireshark-docker.sh <container> <interface> icmp
```

## Practical Notes

- Use tcpdump filters early: `icmp`, `arp`, `tcp port 179`, `host <ip>`, `net <prefix>`.
- Add `-e` to see L2 headers and `-vvv` for deeper protocol decode.
- Add `-s 0` for full packets when capturing to pcap or streaming to Wireshark.
- If a command should produce output but returns nothing, retry with `docker exec -it`.
- Keep SR Linux show commands serial, but tcpdump on a single interface can be run independently from traffic generation.
- Prefer text tcpdump for quick agent-side debugging; use Wireshark when the user needs visual inspection, timelines, TCP details, or field-by-field protocol decoding.
