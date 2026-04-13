#!/bin/bash
# XDP Management script for GEN WAF
# Usage: sudo ./scripts/xdp-manage.sh [attach|detach|status] [interface]

COMMAND=$1
INTERFACE=${2:-eth0}
BPF_OBJ="./bin/genwaf_xdp.bpf.o"

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (sudo)" 
   exit 1
fi

case "$COMMAND" in
    attach)
        echo "Attaching XDP program to $INTERFACE..."
        # Check if ip tool supports xdp
        if ! ip link set dev "$INTERFACE" xdp help > /dev/null 2>&1; then
            echo "Error: 'ip' tool does not support XDP. Please install 'iproute2' or use a newer kernel."
            exit 1
        fi
        
        # Prefer 'ip' for simplicity if available
        ip link set dev "$INTERFACE" xdp obj "$BPF_OBJ" sec xdp_prog
        if [ $? -eq 0 ]; then
            echo "XDP program attached successfully to $INTERFACE."
        else
            echo "Failed to attach XDP program. Ensure the interface exists and supports XDP (generic mode might be needed)."
            echo "Try: ip link set dev $INTERFACE xdp generic obj $BPF_OBJ sec xdp_prog"
        fi
        ;;
    detach)
        echo "Detaching XDP program from $INTERFACE..."
        ip link set dev "$INTERFACE" xdp off
        echo "XDP program detached."
        ;;
    status)
        echo "XDP Status for $INTERFACE:"
        ip link show "$INTERFACE" | grep xdp
        ;;
    *)
        echo "Usage: $0 [attach|detach|status] [interface]"
        exit 1
        ;;
esac
