import Foundation
import NIO
import NIOCore
import NIOSSH

let privateKey =
    """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
    1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRKMl6GDYWg1rVg1TFyWzAHweCc+EN+
    Ko70piPjiVd0XQhR0ysmYnTm+9b16ahe9aI73dBzZl+kG0mzWnZ+W8O7AAAAsBb8hvkW/I
    b5AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEoyXoYNhaDWtWDV
    MXJbMAfB4Jz4Q34qjvSmI+OJV3RdCFHTKyZidOb71vXpqF71ojvd0HNmX6QbSbNadn5bw7
    sAAAAgGn8s3ccM2VsVk0ljNv+rq7ueB//lwxdsOLd2wfb8I04AAAAUY21jZmFybGVuQHBl
    YnMubG9jYWwBAgME
    -----END OPENSSH PRIVATE KEY-----
    """
let publicKey =
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEoyXoYNhaDWtWDVMXJbMAfB4Jz4Q34qjvSmI+OJV3RdCFHTKyZidOb71vXpqF71ojvd0HNmX6QbSbNadn5bw7s= cmcfarlen@pebs.local"

public class SshAgentProcess {
    var agentProcess: Process? = nil

    deinit {
        stop()
    }

    func start() {
        let p = Process()
        p.executableURL = URL(string: "file:///usr/bin/ssh-agent")
        p.arguments = ["-a", agentPath(), "-d"]
        let outputPipe = Pipe()
        let errorPipe = Pipe()

        p.standardOutput = outputPipe
        p.standardError = errorPipe

        do {
            try p.run()

            agentProcess = p
        } catch {
            fatalError("Running ssh agent failed")
        }
    }

    func stop() {
        if let agentProcess {
            print("Stopping ssh agent")
            agentProcess.terminate()
            agentProcess.waitUntilExit()
        }
        agentProcess = nil
    }

    func agentPath() -> String {
        let pid = ProcessInfo.processInfo.processIdentifier

        return "/tmp/niossh-agent-test.\(pid)"
    }

    func waitForAgent() -> String? {
        let path = agentPath()
        let start = Date()

        repeat {
            if FileManager.default.fileExists(atPath: path) {
                return path
            }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date().timeIntervalSince(start) < 1

        return nil
    }

}

let agent = SshAgentProcess()

print("Starting an ssh agent")
agent.start()
print("Waiting for agent to start")
guard let agentPath = agent.waitForAgent() else {
    print("Failed to start agent")
    exit(1)
}

let group = MultiThreadedEventLoopGroup.singleton
let bootstrap = ClientBootstrap(group: group)
    .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
    .channelInitializer { channel in
        // The pipeline processes data and events. Add your handler here.
        channel.pipeline.addHandlers([
            MessageToByteHandler(SshAgentFrameCoder()),
            ByteToMessageHandler(SshAgentFrameCoder()),
            NIOSSHAgentClientHandler(),
            NIOSSHAgentClientTransactionHandler(),
        ])
    }

print("Connecting to \(agent.agentPath())")
let channel = try bootstrap.connect(unixDomainSocketPath: agent.agentPath()).wait()

let makeSyncRequest = { (request: SshAgentRequest) in
    let promise = channel.eventLoop.makePromise(of: SshAgentResponse.self)
    let future = promise.futureResult

    let transaction = SshAgentTransaction(request: request, promise: promise)

    channel.writeAndFlush(transaction, promise: nil)

    return try future.wait()
}

print("Identities before add: \(try makeSyncRequest(.requestIdentities))")

let identity = Identity(pemRepresentation: privateKey)!
print("Response from adding identity \(try makeSyncRequest(.addIdentity(identity)))")

print("Identities after add: \(try makeSyncRequest(.requestIdentities))")

agent.stop()
