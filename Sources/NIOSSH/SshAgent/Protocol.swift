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

/// A request to an SSH Agent.
///
/// This enum represents the various requests that can be sent to an SSH Agent as defined in
/// [draft-miller-ssh-agent-17](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-17).
/// Each case encapsulates the data required for that specific request type.
///
/// Currently supported operations:
/// - ``requestIdentities``: Request a list of all identities stored in the agent
/// - ``signRequest(keyBlob:data:flags:)``: Request the agent sign data with a specific key
/// - ``addIdentity(_:)``: Add a private key identity to the agent
public enum NIOSSHAgentRequest: Sendable {
    /// Request a list of all identities currently stored in the SSH Agent.
    case requestIdentities

    /// Request the SSH Agent sign data using a specific key.
    ///
    /// - Parameters:
    ///   - keyBlob: The public key blob identifying which key to use for signing.
    ///   - data: The data to be signed.
    ///   - flags: SSH Agent signature flags (typically 0).
    case signRequest(keyBlob: ByteBuffer, data: ByteBuffer, flags: UInt32)

    /// Add a private key identity to the SSH Agent.
    ///
    /// - Parameter identity: The identity to add to the agent.
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

    /// Encodes an SSH Agent request into a `ByteBuffer`.
    ///
    /// This method writes the request in the SSH Agent wire protocol format as specified in
    /// [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251#section-5).
    ///
    /// - Parameter buf: The buffer to write the encoded request into.
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

/// An identifier for a key stored in an SSH Agent.
///
/// The SSH Agent does not allow direct access to private keys. This type represents a public key
/// identifier that can be used to reference a key stored in the agent. It is returned from
/// ``NIOSSHAgentRequest/requestIdentities`` and can be used with ``NIOSSHAgentRequest/signRequest(keyBlob:data:flags:)``
/// to perform cryptographic operations without exposing the private key material.
public struct NIOSSHAgentKeyIdentifier: Hashable, Sendable {
    /// The public key blob in SSH wire format.
    public let key: ByteBuffer

    /// A comment associated with this identity, typically identifying the key's origin or purpose.
    public let comment: String
}

extension NIOSSHAgentKeyIdentifier: CustomStringConvertible {
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

/// A response from an SSH Agent.
///
/// This structure encapsulates all possible responses an SSH Agent can send, as defined in
/// [draft-miller-ssh-agent-17](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-17).
/// The actual response data is contained in the ``response`` property.
public struct NIOSSHAgentResponse: Sendable, Hashable {
    /// The types of responses an SSH Agent can send.
    public enum Response: Sendable, Hashable {
        /// The operation succeeded (no data returned).
        case generalSuccess

        /// The operation failed.
        case generalFailure

        /// A list of identities stored in the agent.
        ///
        /// This is the response to ``NIOSSHAgentRequest/requestIdentities``.
        case identities([NIOSSHAgentKeyIdentifier])

        /// A signature generated by the agent.
        ///
        /// This is the response to ``NIOSSHAgentRequest/signRequest(keyBlob:data:flags:)``.
        /// The buffer contains the signature in SSH wire format.
        case signResponse(ByteBuffer)

        /// The agent received a message type it does not yet support.
        ///
        /// - Parameter message: The unsupported message number.
        case notYetSupported(message: UInt8)
    }

    /// The actual response from the SSH Agent.
    public let response: Response

    public static let generalSuccess: NIOSSHAgentResponse = .init(response: .generalSuccess)
    public static let generalFailure: NIOSSHAgentResponse = .init(response: .generalFailure)

    public static func identities(_ ids: [NIOSSHAgentKeyIdentifier]) -> NIOSSHAgentResponse {
        .init(response: .identities(ids))
    }

    public static func signResponse(_ bytes: ByteBuffer) -> NIOSSHAgentResponse {
        .init(response: .signResponse(bytes))
    }

    public static func notYetSupported(message: UInt8) -> NIOSSHAgentResponse {
        .init(response: .notYetSupported(message: message))
    }
}

extension ByteBuffer {
    mutating func readAgentIdentityList() throws -> [NIOSSHAgentKeyIdentifier] {
        guard let nKeys: UInt32 = self.readInteger() else {
            // An ssh agent should always provide the number of keys here, so if this read fails
            // its a fail
            throw NIOSSHAgentError.badResponse
        }
        var result: [NIOSSHAgentKeyIdentifier] = []
        result.reserveCapacity(Int(nKeys))

        for _ in 0..<nKeys {
            guard
                let key = self.readSSHString(),
                let comment = self.readSSHStringAsString()
            else {
                throw NIOSSHAgentError.partialResponse(expected: Int(nKeys), received: result.count)
            }
            result.append(NIOSSHAgentKeyIdentifier(key: key, comment: comment))
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
