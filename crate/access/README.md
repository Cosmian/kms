# Cosmian KMS Access

The **Access** crate provides user permission and access control management for the Cosmian KMS.

## Overview

This crate implements the access control system that manages user permissions and authorization policies within the KMS. It provides fine-grained control over who can perform what operations on which resources.

## Features

- **User Management**: Handle user identities and authentication
- **Permission System**: Define and enforce granular permissions for KMS operations
- **Role-Based Access Control (RBAC)**: Support for role-based permission assignment
- **Resource-Level Security**: Control access to specific keys, certificates, and other cryptographic objects
- **Audit Trail**: Track access attempts and permission changes

## Key Components

- **Access Control Lists (ACL)**: Manage permissions for specific resources
- **User Authorization**: Validate user permissions for requested operations
- **Permission Models**: Define various permission types (read, write, admin, etc.)
- **Integration**: Seamless integration with KMS core operations

## Usage

This crate is primarily used internally by the KMS server to enforce access controls. It integrates with the authentication system to provide comprehensive security for all KMS operations.

## Dependencies

- `cosmian_kmip` - For KMIP protocol types and structures
- `serde` - For serialization of access control data

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
