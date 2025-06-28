//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// SSH Agent protocol as described here:
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-17
// and using the wire representation described here:
// https://datatracker.ietf.org/doc/html/rfc4251#section-5
//

import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

enum MessageNumber: UInt8, Sendable {
    case requestIdentities = 11
    case signRequest = 13
    case addIdentity = 17
    case removeIdentity = 18
    case removeAllIdentities = 19
    case addSmartcardKey = 20
    case removeSmartcardKey = 21
    case lock = 22
    case unlock = 23
    case addIdConstrained = 25
    case addSmartcardKeyContrained = 26
    case messageExtension = 27
    case failure = 5
    case success = 6
    case identitiesAnswer = 12
    case signResponse = 14
    case extensionFailure = 28
    case extensionResponse = 29
}

/// A request to an SSH Agent
///
/// This enum handles the encoding of requests to `ByteBuffer`s
public enum NIOSSHAgentRequest: Sendable {
    case requestIdentities
    case signRequest(keyBlob: ByteBuffer, data: ByteBuffer, flags: UInt32)
    case addIdentity(NIOSSHAgentIdentity)

    var messageNumber: MessageNumber {
        switch self {
        case .requestIdentities:
            .requestIdentities
        case .signRequest:
            .signRequest
        case .addIdentity:
            .addIdentity
        }
    }

    /// Encodes a SSH Agent request into a `ByteBuffer`
    package func encode(into buf: inout ByteBuffer) {
        buf.writeInteger(messageNumber.rawValue)

        switch self {
        case .signRequest(keyBlob: let blob, let data, let flags):
            buf.writeLengthPrefixedBuffer(blob, strategy: .sshAgent)
            buf.writeLengthPrefixedBuffer(data, strategy: .sshAgent)
            buf.writeInteger(flags)
        case .addIdentity(let id):
            for var bb in id.identity {
                buf.writeSSHString(&bb)
            }
        default:
            break
        }
    }
}

/// An identifier representing an Agent stored identity
///
/// The SSH Agent doesn't allow direct access to private keys
/// so this type represents the public identity and is used
/// as a key to the SSH Agent when performing operations
public struct NIOSSHIdentity: Hashable, Sendable {
    public let key: ByteBuffer
    public let comment: String
}

extension NIOSSHIdentity: CustomStringConvertible {
    public var description: String {
        var bb = ByteBuffer(buffer: key)
        guard
            let id = bb.readSSHStringAsString(),
            let bytes = bb.readSSHString()
        else {
            return "unknown \(key) \(comment)"
        }

        return "\(id) \(Data(bytes.readableBytesView).base64EncodedString()) \(comment)"
    }
}

/// A response from the SSH Agent
public enum NIOSSHAgentResponse: Sendable, Hashable {
    case generalSuccess
    case generalFailure
    case identities([NIOSSHIdentity])
    case signResponse(ByteBuffer)
    case notYetSupported(message: UInt8)
}

extension ByteBuffer {
    mutating func readAgentIdentityList() throws -> [NIOSSHIdentity] {
        guard let nKeys: UInt32 = self.readInteger() else {
            return []
        }
        var result: [NIOSSHIdentity] = []
        result.reserveCapacity(Int(nKeys))

        for _ in 0..<nKeys {
            guard
                let key = self.readSSHString(),
                let comment = self.readSSHStringAsString()
            else {
                return result
            }
            result.append(NIOSSHIdentity(key: key, comment: comment))
        }

        if self.readableBytes > 0 {
            throw NIOSSHAgentError.trailingBytes
        }

        return result
    }

    mutating func readSSHAgentResponse() throws -> NIOSSHAgentResponse {
        guard let messageNumber: UInt8 = self.readInteger(),
            let number = MessageNumber(rawValue: messageNumber)
        else {
            throw NIOSSHAgentError.badResponse
        }
        switch number {
        case .identitiesAnswer:
            return .identities(try readAgentIdentityList())
        case .signResponse:
            if let sig = self.readSSHString() {
                return .signResponse(sig)
            } else {
                return .generalFailure
            }
        case .failure:
            return .generalFailure
        case .success:
            return .generalSuccess
        default:
            return .notYetSupported(message: number.rawValue)
        }

    }
}
