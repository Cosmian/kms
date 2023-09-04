
The Cosmian KMS has been designed to run in the cloud or any zero-trust environment.

The design rely on 3 features:

 - running the KMS server in a confidential VM
 - starting the server in bootstrapping mode
 - using application-level encryption for the database data and indexes


#### Running the KMS server in a confidential VM

Confidential VMs are standard virtual machines running on servers with additional hardware components that ensure encryption of memory at runtime using a secret hidden in the CPU. Confidential VMs protect the KMS server from runtime attacks such as memory dumping and snooping from attackers with physical access to the server and hence offer protection against attacks that could be performed by a malicious cloud provider, or zero-trust environment operator.
Confidential VMs are found on machines running CPUs with AMD-SEV SNP technology, and Intel SGX or TDX technology. They are now available at all major cloud providers.



