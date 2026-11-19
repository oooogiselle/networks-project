# ============================================================================
# File Name:   demo_log.awk
# Author:      Eva Tate and Giselle Wu, assisted by Claude Code
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: Makes tunwall's log readable on camera: drops the columns that
#              are noise on a projector (rule number, packet and byte counts,
#              duration) and colours the lines. red = dropped packet, green =
#              flow opened, cyan = application identified, magenta = the port
#              disagrees with the payload, grey = flow closed or expired,
#              yellow = a port scanner was blocked (SCAN) or let go (UNBLOCK).
# ============================================================================
{
    gsub(/ rule=[0-9]+/, "")
    gsub(/ pkts=[0-9\/]+ bytes=[0-9\/]+/, "")
    gsub(/ dur=[0-9.]+s/, "")
    if      ($0 ~ /mismatch\(/)           c = "1;35"
    else if ($0 ~ / (SCAN|UNBLOCK) /)     c = "1;33"
    else if ($0 ~ / DROP /)               c = "31"
    else if ($0 ~ /FLOW NEW/)             c = "32"
    else if ($0 ~ /FLOW APP/)             c = "36"
    else if ($0 ~ /FLOW (CLOSE|EXPIRE)/)  c = "90"
    else if ($0 ~ /^tunwall:/)            c = "1"
    else                                  c = ""
    if (c != "") printf "\033[%sm%s\033[0m\n", c, $0
    else print $0
    fflush()
}
