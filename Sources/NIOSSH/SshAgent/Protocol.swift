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

struct MessageNumber: Sendable, Equatable {
    let rawValue: UInt8

    static let requestIdentities = MessageNumber(rawValue: 11)
    static let signRequest = MessageNumber(rawValue: 13)
    static let addIdentity = MessageNumber(rawValue: 17)
    static let removeIdentity = MessageNumber(rawValue: 18)
    static let removeAllIdentities = MessageNumber(rawValue: 19)
    static let addSmartcardKey = MessageNumber(rawValue: 20)
    static let removeSmartcardKey = MessageNumber(rawValue: 21)
    static let lock = MessageNumber(rawValue: 22)
    static let unlock = MessageNumber(rawValue: 23)
    static let addIdConstrained = MessageNumber(rawValue: 25)
    static let addSmartcardKeyContrained = MessageNumber(rawValue: 26)
    static let messageExtension = MessageNumber(rawValue: 27)
    static let failure = MessageNumber(rawValue: 5)
    static let success = MessageNumber(rawValue: 6)
    static let identitiesAnswer = MessageNumber(rawValue: 12)
    static let signResponse = MessageNumber(rawValue: 14)
    static let extensionFailure = MessageNumber(rawValue: 28)
    static let extensionResponse = MessageNumber(rawValue: 29)
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
        case .signRequest(keyBlob: var blob, var data, let flags):
            buf.writeSSHString(&blob)
            buf.writeSSHString(&data)
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

/// SshIdentity represents a key pair stored in the ssh-agent
///
/// The ssh-agent does not expose private keys, so for auth you must
/// ask the agent to sign data on your behalf.  The request identities
/// command to a ssh-agent will return the list of public keys that
/// can be used for sign requests.
/// Its fine to leave the keys as opaque bytes here as they
/// are only used to hand back to the ssh-agent for signature requests
public struct NIOSSHIdentity: Hashable, Sendable {
    public let key: ByteBuffer
    public let comment: String

    public var keyBlob: [UInt8] {
        key.getBytes(at: 0, length: key.readableBytes) ?? []
    }
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

        return "\(id) \(Data(key.readableBytesView).base64EncodedString()) \(comment)"
    }

    public var publicKey: NIOSSHPublicKey {
        // TODO(cmcfarlen): Init from raw respresentation without roundtrip to string
        do {
            return try NIOSSHPublicKey(openSSHPublicKey: description)
        } catch {
            fatalError("Failed to convert public key: \(error)")
        }
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
        guard let messageNumber: UInt8 = self.readInteger() else {
            throw NIOSSHAgentError.badResponse
        }
        let number = MessageNumber(rawValue: messageNumber)
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
