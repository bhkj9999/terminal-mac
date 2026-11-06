"""Act as a guest NIC against gvproxy and open a TCP connection to 192.168.127.254:PORT,
which gvproxy should map to a listener on the host's 127.0.0.1:PORT.
Normally run through scripts/probe-userspace-network.sh.
Usage: python3 -I probe-userspace-network.py <gvproxy-socket> <local-socket> <port>"""
import socket, struct, sys, os, time, threading

GV, LOC, PORT = sys.argv[1], sys.argv[2], int(sys.argv[3])
MAC = bytes.fromhex("020000000001")
HOST_ALIAS = socket.inet_aton("192.168.127.254")

# Stand-in for LiteLLM on the host's localhost.
ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", PORT)); ls.listen(1)
seen = {}
def serve():
    c, _ = ls.accept()
    seen["request"] = c.recv(100)
    c.sendall(b"pong-from-host"); c.close()
threading.Thread(target=serve, daemon=True).start()

def csum(b):
    if len(b) % 2: b += b"\0"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while t >> 16: t = (t & 0xFFFF) + (t >> 16)
    return ~t & 0xFFFF

def ip_pkt(src, dst, proto, payload):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, 0x4000, 64, proto, 0, src, dst)
    return h[:10] + struct.pack("!H", csum(h)) + h[12:] + payload

def tcp_seg(src, dst, sport, dport, seq, ack, flags, payload=b""):
    h = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 65535, 0, 0)
    c = csum(src + dst + struct.pack("!BBH", 0, 6, len(h) + len(payload)) + h + payload)
    return h[:16] + struct.pack("!H", c) + h[18:] + payload

def eth(dst, etype, payload): return dst + MAC + etype + payload

if os.path.exists(LOC): os.unlink(LOC)
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(LOC); s.connect(GV); s.settimeout(1)
s.send(b"VFKT")

# DHCP DISCOVER to learn our address and the gateway's MAC.
bootp = struct.pack("!BBBBIHHIIII", 1, 1, 6, 0, 0x1234abcd, 0, 0x8000, 0, 0, 0, 0)
bootp += MAC + b"\0" * 10 + b"\0" * 64 + b"\0" * 128 + bytes([0x63, 0x82, 0x53, 0x63, 53, 1, 1, 255])
udp = struct.pack("!HHHH", 68, 67, 8 + len(bootp), 0) + bootp
s.send(eth(b"\xff" * 6, b"\x08\x00", ip_pkt(bytes(4), b"\xff" * 4, 17, udp)))
my_ip = gw_mac = None
end = time.time() + 3
while time.time() < end and not my_ip:
    try: d = s.recv(4096)
    except socket.timeout: continue
    if d[12:14] == b"\x08\x00" and d[23] == 17 and d[34:36] == b"\x00\x43":
        my_ip = d[34 + 8 + 16:34 + 8 + 20]; gw_mac = d[6:12]
print("guest address:", socket.inet_ntoa(my_ip) if my_ip else None)
if not my_ip: sys.exit("no DHCP offer")

sport, seq = 40000, 1000
s.send(eth(gw_mac, b"\x08\x00", ip_pkt(my_ip, HOST_ALIAS, 6, tcp_seg(my_ip, HOST_ALIAS, sport, PORT, seq, 0, 0x02))))
state, reply, end = "syn-sent", b"", time.time() + 6
while time.time() < end and state != "done":
    try: d = s.recv(4096)
    except socket.timeout: continue
    et = d[12:14]
    if et == b"\x08\x06" and d[20:22] == b"\x00\x01" and d[38:42] == my_ip:   # ARP request for us: answer it
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + MAC + my_ip + d[22:28] + d[28:32]
        s.send(d[6:12] + MAC + b"\x08\x06" + arp)
        continue
    if et != b"\x08\x00" or d[23] != 6: continue
    ihl = (d[14] & 15) * 4; t = d[14 + ihl:]
    flags, tseq, tack = t[13], struct.unpack("!I", t[4:8])[0], struct.unpack("!I", t[8:12])[0]
    payload = t[(t[12] >> 4) * 4:]
    if state == "syn-sent" and flags & 0x12 == 0x12:
        print("SYN-ACK from", socket.inet_ntoa(d[26:30]), "-> TCP handshake to host localhost works")
        seq += 1; srv = tseq + 1
        s.send(eth(gw_mac, b"\x08\x00", ip_pkt(my_ip, HOST_ALIAS, 6, tcp_seg(my_ip, HOST_ALIAS, sport, PORT, seq, srv, 0x10))))
        msg = b"ping-from-guest"
        s.send(eth(gw_mac, b"\x08\x00", ip_pkt(my_ip, HOST_ALIAS, 6, tcp_seg(my_ip, HOST_ALIAS, sport, PORT, seq, srv, 0x18, msg))))
        state = "sent"
    elif state == "sent" and payload:
        reply = payload; state = "done"
    elif flags & 0x04:
        print("RST from host side"); break
print("listener on host received:", seen.get("request"))
print("guest received:", reply or None)
os.unlink(LOC)
ok = reply == b"pong-from-host" and seen.get("request") == b"ping-from-guest"
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
