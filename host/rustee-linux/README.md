# rustee-linux

Future out-of-tree `rustee-virt.ko` (GPL-2.0-only). Not in the TEE TCB.
v0: registers with `tee.ko`, copies shm into a 16MiB bounce pool, AF_VSOCK to guest CID 3 port 7007.
Do not add C sources until the driver lands.
