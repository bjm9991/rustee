# rustee-linux

Out-of-tree `rustee_virt.ko` (**GPL-2.0-only**). Not in the TEE TCB.

v0: registers with `tee.ko`, 16MiB host bounce pool, AF_VSOCK SOCK_STREAM to
guest CID 3 port 7007. virtio REQUEST/RESPONSE is vhost, not this module.
Fast SMCCC answered here. Yielding `CALL_WITH_ARG` on vsock: PDU arg is a
64-byte CallFrame; MSG is in bounce at cookie a1:a2 (a1 high 32, a2 low 32).
The bounce window starts at cookie (HAL copies the PDU payload onto
`pool[cookie]`). `tmem.buf_ptr` is a pool offset.

Open/invoke pack MSG + memref copies, send ENTER, wait for COMPLETE (one
outstanding call). Guest RPC is answered by `rustee-supplicant` on the
userspace `gp-client` `StreamTransport` path until teepriv exists.

```
make KDIR=/path/to/kernel
```

CUSE is bring-up only, not the xtest path. Native `drivers/tee/rustee/` is v1.
