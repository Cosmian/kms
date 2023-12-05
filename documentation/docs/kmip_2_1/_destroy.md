#### specification

This operation is used to indicate to the server that the key material for the specified Managed Object SHALL be destroyed or rendered inaccessible. The meta-data for the key material SHALL be retained by the server. Objects SHALL only be destroyed if they are in either Pre-Active or Deactivated state.

#### implementation

Destroyed keys are set in the state `destroyed` on the Cosmian KMS Server.