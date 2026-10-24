# Operations

In [chapter 6](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html#_Toc57115631), the KMIP 2.1
specifications describe 57 potential operations that can be performed on a KMS.

## Supported Operations

The list of supported Operations is that of the menu entries below this one. See the
[KMIP support](./support.md) page for the full matrix.

## Messages and Bulk Operations

A KMIP request may be made by POSTing a single Operation serialized as JSON TTLV, or by combining multiple operations
in a `Message` request. See the [bulk mode](./messages.md) page for more details.

## ID Placeholder

ID Placeholders work within one Request Message. Operations that create or select one object set it; later items
that omit the Unique Identifier use it. If none is present, the item returns `Invalid_Message`. Bare operations
posted to `/kmip/2_1` have no ID Placeholder.
