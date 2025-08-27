# Cosmian KMS Server Database

The **Server Database** crate provides database abstraction and storage implementations for the Cosmian KMS server.

## Overview

This crate implements the database layer that handles persistent storage of cryptographic objects, metadata, access control information, and audit logs. It supports multiple database backends and provides a unified interface for all storage operations.

## Supported Database Backends

### SQLite

- **Local Storage**: File-based database for development and small deployments
- **In-Memory**: For testing and temporary storage
- **Encryption**: Support for SQLCipher encrypted databases
- **Performance**: Optimized for single-node deployments

### PostgreSQL

- **Production Ready**: Full-featured relational database
- **High Availability**: Support for replication and clustering
- **ACID Compliance**: Full transaction support
- **Scalability**: Suitable for large-scale deployments

### MySQL/MariaDB

- **Compatibility**: Support for MySQL and MariaDB
- **Performance**: Optimized queries and indexing
- **Replication**: Master-slave and master-master setups
- **Cloud Ready**: Compatible with cloud database services

### Redis with Findex (Non-FIPS)

- **Searchable Encryption**: Encrypted search capabilities using Cloudproof Findex
- **High Performance**: In-memory storage for ultra-fast operations
- **Distributed**: Support for Redis clusters
- **Privacy Preserving**: Search without revealing query patterns

## Features

### Core Functionality

- **Object Storage**: Secure storage of keys, certificates, and cryptographic objects
- **Metadata Management**: Storage of object attributes, tags, and relationships
- **Access Control**: User permissions and role-based access control data
- **Audit Logging**: Comprehensive logging of all database operations

### Database Operations

- **CRUD Operations**: Create, Read, Update, Delete for all object types
- **Batch Operations**: Efficient bulk operations for large datasets
- **Transactions**: ACID transactions for data consistency
- **Connection Pooling**: Efficient database connection management

### Security Features

- **Encryption at Rest**: Database-level encryption for sensitive data
- **Access Control**: Fine-grained permissions and user management
- **Audit Trail**: Complete logging of all database access and modifications
- **Data Integrity**: Checksums and validation for stored objects

### Performance Optimizations

- **Caching**: LRU cache for frequently accessed objects
- **Indexing**: Optimized database indexes for fast queries
- **Connection Pooling**: Efficient database connection reuse
- **Async Operations**: Non-blocking database operations

## Architecture

### Database Abstraction Layer

The crate provides a unified interface that abstracts the underlying database implementation:

- **Common API**: Single interface for all database operations
- **Backend Agnostic**: Switch between database types without code changes
- **Error Handling**: Unified error types across all backends
- **Configuration**: Simple configuration for different database types

### Object Serialization

- **KMIP Format**: Native KMIP object serialization
- **JSON Support**: Human-readable JSON format for debugging
- **Binary Efficiency**: Compact binary storage for performance
- **Version Compatibility**: Support for different KMIP versions

## Configuration

### Environment Variables

- `KMS_POSTGRES_URL`: PostgreSQL connection string
- `KMS_MYSQL_URL`: MySQL/MariaDB connection string
- `KMS_SQLITE_PATH`: SQLite database file path
- `KMS_REDIS_URL`: Redis connection string for Findex

### Connection Examples

```bash
# PostgreSQL
KMS_POSTGRES_URL=postgresql://user:password@host:5432/database

# MySQL
KMS_MYSQL_URL=mysql://user:password@host:3306/database

# SQLite
KMS_SQLITE_PATH=/path/to/database.db

# Redis (for Findex)
KMS_REDIS_URL=redis://host:6379
```

## Dependencies

### Core Dependencies

- **sqlx**: SQL database toolkit for async operations
- **redis**: Redis client for Findex support
- **cloudproof_findex**: Searchable encryption (optional)
- **cosmian_kmip**: KMIP protocol types
- **cosmian_kms_crypto**: Cryptographic operations
- **cosmian_kms_interfaces**: Interface definitions

### Database Drivers

- **PostgreSQL**: Native async driver via sqlx
- **MySQL**: Native async driver via sqlx
- **SQLite**: Native async driver via sqlx
- **Redis**: Async Redis client

## Usage

This crate is used internally by the KMS server to provide persistent storage. It handles:

- Key and certificate storage
- User authentication data
- Access control policies
- Audit logs and operation history
- Configuration and metadata

## Performance Considerations

- **Connection Pooling**: Configurable connection pool sizes
- **Caching**: LRU cache for frequently accessed objects
- **Indexing**: Optimized database indexes for common queries
- **Batch Operations**: Efficient bulk insert/update operations

## Security

- **Encryption**: All sensitive data is encrypted before storage
- **Access Control**: Database-level and application-level security
- **Audit Logging**: Complete audit trail of all operations
- **Data Validation**: Input validation and sanitization

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
