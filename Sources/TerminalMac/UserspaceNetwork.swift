import Foundation
import Virtualization
import Darwin
import TerminalMacCore

/// Optional userspace networking through gvproxy (gvisor-tap-vsock), the same approach Podman and Lima use.
/// The guest's Ethernet frames go to a gvproxy process over a unixgram socket and leave the Mac as ordinary
/// sockets of that process, so they follow the host's normal routes (including a VPN) rather than the
/// vmnet bridge that NAT uses. Enabled by TERMINAL_MAC_GVPROXY=/absolute/path/to/gvproxy.
/// Guest side: subnet 192.168.127.0/24, gateway 192.168.127.1, DNS via the gateway.
nonisolated(unsafe) private var gvproxyProcess: Process?

enum UserspaceNetwork {
    static func attachment(for machine: Machine, binary: String?) throws -> VZNetworkDeviceAttachment? {
        guard let binary, !binary.isEmpty else { return nil }
        guard FileManager.default.isExecutableFile(atPath: binary) else { throw Failure("TERMINAL_MAC_GVPROXY is not an executable file: \(binary)") }
        // Socket paths are limited to ~104 bytes, so they live in /tmp rather than the VM directory.
        let base = "/tmp/terminal-mac-\(getuid())-\(machine.name)"
        let server = base + "-gv.sock", client = base + "-vm.sock", pidFile = base + "-gv.pid"
        guard server.utf8.count < 100, client.utf8.count < 100 else { throw Failure("VM name is too long for a unix socket path") }
        // A gvproxy left behind by a killed run would still own the socket.
        if let text = try? String(contentsOfFile: pidFile, encoding: .utf8), let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 1 {
            kill(pid, SIGTERM); usleep(200_000)
        }
        unlink(server); unlink(client); unlink(pidFile)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        // -ssh-port -1: no forward of localhost:2222 into the guest.
        // TERMINAL_MAC_GVPROXY_ARGS adds gvproxy flags for debugging, e.g. "-debug -log-file /tmp/gv.log -pcap /tmp/gv.pcap".
        let extra = (ProcessInfo.processInfo.environment["TERMINAL_MAC_GVPROXY_ARGS"] ?? "").split(separator: " ").map(String.init)
        process.arguments = ["-listen-vfkit", "unixgram://" + server, "-ssh-port", "-1", "-pid-file", pidFile] + extra
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        gvproxyProcess = process
        atexit { gvproxyProcess?.terminate() }

        var waited = 0
        while !FileManager.default.fileExists(atPath: server) {
            guard process.isRunning, waited < 50 else { throw Failure("gvproxy did not start. Run it by hand to see why: \(binary) -listen-vfkit unixgram://\(server) -ssh-port -1") }
            usleep(100_000); waited += 1
        }

        let fd = socket(AF_UNIX, SOCK_DGRAM, 0)
        guard fd >= 0 else { throw Failure("Cannot create network socket") }
        var local = address(client), remote = address(server)
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &local) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, size) } }
        let connected = withUnsafePointer(to: &remote) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, size) } }
        guard bound == 0, connected == 0 else { close(fd); throw Failure("Cannot connect to gvproxy: \(String(cString: strerror(errno)))") }
        // Virtualization's guidance for datagram attachments: receive buffer at least 4x the send buffer.
        var sendBuffer: Int32 = 1 << 20, receiveBuffer: Int32 = 4 << 20
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sendBuffer, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receiveBuffer, socklen_t(MemoryLayout<Int32>.size))
        // gvproxy learns the VM's socket address from this first datagram.
        _ = "VFKT".withCString { send(fd, $0, 4, 0) }
        stderr("Networking: userspace via gvproxy (192.168.127.0/24).")
        return VZFileHandleNetworkDeviceAttachment(fileHandle: FileHandle(fileDescriptor: fd, closeOnDealloc: false))
    }

    private static func address(_ path: String) -> sockaddr_un {
        var value = sockaddr_un()
        value.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        value.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &value.sun_path) { buffer in
            for (index, byte) in path.utf8.enumerated() where index < buffer.count - 1 { buffer[index] = byte }
        }
        return value
    }
}
