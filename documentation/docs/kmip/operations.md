In [chapter 6](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html#_Toc32239394), the KMIP 2.1
specifications describe 57 potential operations that can be performed on a KMS.

### Supported Operations

Out of this list, the Cosmian KMS server only requires 12 operations to provide all required functionalities to support
the cryptographic schemes available on the server.

The list of supported Operations is that of the menu entries below this one.

### Messages and Bulk Operations

A KMIP request may be made by POSTing a single Operation serialized as JSON TTLV, or by combining multiple operations
in a `Message` request. See the [bulk mode](./messages.md) page for more details.

### No support for "ID Placeholders"

KMIP states that a number of the operations are affected by a mechanism referred to as the ID Placeholder. It is a
variable stored inside the server that is preserved during the execution of a batch of operations.

Maintaining this value requires maintaining a state during a batch session across multiple requests and potentially
multiple servers. The performance gain of using placeholder IDs is not obvious, and the added complexity of maintaining
sessions across multiple servers when scaling horizontally is not worth in the Cosmian view for the type of operations
conducted on the server.

The Cosmian KMS servers are kept stateless to simplify horizontal scaling and therefore do not support placeholder IDs
for now.
