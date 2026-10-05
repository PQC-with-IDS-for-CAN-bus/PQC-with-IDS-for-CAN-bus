#!/usr/bin/env bash
# ==============================================================================
# setup_topology.sh — Plumb vxcan interfaces across DockerLab containers
# ==============================================================================
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run with sudo: sudo ./setup_topology.sh"
    exit 1
fi

echo "[*] Ensuring CAN kernel modules are loaded..."
modprobe can 2>/dev/null || true
modprobe can_raw 2>/dev/null || true
modprobe vxcan 2>/dev/null || true

echo "[*] Discovering container PIDs..."
get_pid() {
    local name="$1"
    local pid=""
    for i in {1..20}; do
        pid=$(docker inspect -f '{{.State.Pid}}' "$name" 2>/dev/null || true)
        if [ -n "$pid" ] && [ "$pid" -gt 1 ]; then
            echo "$pid"
            return 0
        fi
        if [ "$name" = "dockerlab-attacker" ] && [ "$i" -eq 1 ]; then
            echo "[*] Attempting to auto-start dockerlab-attacker..." >&2
            docker compose up -d attacker 2>/dev/null || true
        fi
        sleep 1
    done

    echo "[!] Container $name is not running (PID=$pid)." >&2
    echo "[!] Container inspection status:" >&2
    docker inspect -f 'Status: {{.State.Status}}, ExitCode: {{.State.ExitCode}}, Error: {{.State.Error}}' "$name" 2>&1 >&2 || true
    echo "[!] Container logs:" >&2
    docker logs --tail 20 "$name" 2>&1 >&2 || true
    echo "[!] Please start the containers first with: sudo docker compose up -d" >&2
    exit 1
}

RELAY_PID=$(get_pid dockerlab-relay)
GATEWAY_PID=$(get_pid dockerlab-gateway)
ATTACKER_PID=$(get_pid dockerlab-attacker)
ECU1_PID=$(get_pid dockerlab-ecu1)
ECU2_PID=$(get_pid dockerlab-ecu2)
ECU3_PID=$(get_pid dockerlab-ecu3)
ECU4_PID=$(get_pid dockerlab-ecu4)

echo "[+] Container PIDs:"
echo "    Relay:    $RELAY_PID"
echo "    Gateway:  $GATEWAY_PID"
echo "    Attacker: $ATTACKER_PID"
echo "    ECU1:     $ECU1_PID"
echo "    ECU2:     $ECU2_PID"
echo "    ECU3:     $ECU3_PID"
echo "    ECU4:     $ECU4_PID"

echo "[*] Plumbing vxcan interfaces across domains 1..4..."
for d in 1 2 3 4; do
    case $d in
        1) ecu_pid=$ECU1_PID ;;
        2) ecu_pid=$ECU2_PID ;;
        3) ecu_pid=$ECU3_PID ;;
        4) ecu_pid=$ECU4_PID ;;
    esac

    # Delete existing vxcan links if present
    nsenter -t "$RELAY_PID" -n -- ip link del "e$d" 2>/dev/null || true
    nsenter -t "$RELAY_PID" -n -- ip link del "g$d" 2>/dev/null || true

    # Create vxcan: Relay e{d} <-> ECU can0
    nsenter -t "$RELAY_PID" -n -- ip link add "e$d" type vxcan peer name can0 netns "$ecu_pid"
    nsenter -t "$RELAY_PID" -n -- ip link set "e$d" up
    nsenter -t "$ecu_pid" -n -- ip link set can0 up

    # Create vxcan: Relay g{d} <-> Gateway domain{d}
    nsenter -t "$RELAY_PID" -n -- ip link add "g$d" type vxcan peer name "domain$d" netns "$GATEWAY_PID"
    nsenter -t "$RELAY_PID" -n -- ip link set "g$d" up
    nsenter -t "$GATEWAY_PID" -n -- ip link set "domain$d" up

    echo "    Domain $d: (relay:e$d <-> ecu$d:can0) and (relay:g$d <-> gateway:domain$d) [UP]"
done

# Attacker: Relay a1 <-> Attacker can0
nsenter -t "$RELAY_PID" -n -- ip link del "a1" 2>/dev/null || true
nsenter -t "$RELAY_PID" -n -- ip link add a1 type vxcan peer name can0 netns "$ATTACKER_PID"
nsenter -t "$RELAY_PID" -n -- ip link set a1 up
nsenter -t "$ATTACKER_PID" -n -- ip link set can0 up
echo "    Attacker: (relay:a1 <-> attacker:can0) [UP]"

echo "[+] Successfully plumbed all 9 vxcan pairs! Virtual CAN bus topology is active."
