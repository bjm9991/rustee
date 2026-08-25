// SPDX-License-Identifier: GPL-2.0-only
/*
 * rustee-virt.ko — v0 virt transport for RUSTEE.
 * Registers with tee.ko, copies TEE_IOC shm into a 16MiB host bounce pool,
 * yields over AF_VSOCK (guest CID 3 port 7007).
 *
 * Fast SMCCC (CALLS_UID, OS UUID, revision 0.1.0, caps, thread count,
 * GET_SHM_CONFIG=ENOTAVAIL) is answered here. Yielding CALL_WITH_ARG only
 * on vsock. PDU arg is a 64-byte CallFrame; MSG lives in bounce at cookie
 * a1:a2 (a1 high 32, a2 low 32). Not TCB.
 *
 * RPC (KIND_RPC) is answered by rustee-supplicant on the userspace
 * gp-client StreamTransport path. This module returns COMMS if the guest
 * RPCs before teepriv exists.
 */
#include <linux/module.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/tee_drv.h>
#include <linux/unaligned.h>
#include <linux/vmalloc.h>
#include <net/sock.h>
#include <uapi/linux/vm_sockets.h>

#define RUSTEE_BOUNCE_SIZE	(16u * 1024u * 1024u)
#define RUSTEE_VSOCK_CID	3u
#define RUSTEE_VSOCK_PORT	7007u
#define RUSTEE_CALLFRAME_LEN	64u
#define RUSTEE_PDU_HDR_LEN	16u
#define RUSTEE_KIND_ENTER	1u
#define RUSTEE_KIND_RPC		2u
#define RUSTEE_KIND_COMPLETE	3u
#define RUSTEE_KIND_RPC_REPLY	4u

#define SMC_CALLS_UID		0xBF00FF01u
#define SMC_GET_OS_UUID		0xB2000000u
#define SMC_GET_OS_REVISION	0xB2000001u
#define SMC_GET_SHM_CONFIG	0xB2000007u
#define SMC_EXCHANGE_CAPS	0xB2000009u
#define SMC_GET_THREAD_COUNT	0xB200000Fu
#define SMC_CALL_WITH_ARG	0x32000004u
#define SMC_RETURN_OK		0u
#define SMC_RETURN_ENOTAVAIL	7u
#define V0_SEC_CAPS		((1u << 1) | (1u << 2) | (1u << 4))

#define TEEC_ERROR_BUSY		0xFFFF000Du
#define TEEC_ERROR_COMMUNICATION 0xFFFF000Eu
#define TEEC_ERROR_NOT_IMPLEMENTED 0xFFFF0009u
#define TEEC_ORIGIN_COMMS	2u

static const u32 rustee_calls_uid[4] = {
	0x384fb3e0u, 0xe7f811e3u, 0xaf630002u, 0xa5d5c51bu
};
static const u32 rustee_os_uuid[4] = {
	0xe819d7dfu, 0x5ffe45e6u, 0xa1133233u, 0x49b219aau
};

struct rustee_priv {
	void *bounce;
	struct socket *vsock;
	u32 seq;
	bool yielding;
};

static int rustee_answer_fast(u32 a0, u32 *a1, u32 *a2, u32 *a3)
{
	switch (a0) {
	case SMC_CALLS_UID:
		*a1 = rustee_calls_uid[1];
		*a2 = rustee_calls_uid[2];
		*a3 = rustee_calls_uid[3];
		return rustee_calls_uid[0];
	case SMC_GET_OS_UUID:
		*a1 = rustee_os_uuid[1];
		*a2 = rustee_os_uuid[2];
		*a3 = rustee_os_uuid[3];
		return rustee_os_uuid[0];
	case SMC_GET_OS_REVISION:
		*a1 = 1;
		*a2 = 0;
		*a3 = 0;
		return 0;
	case SMC_EXCHANGE_CAPS:
		*a1 = V0_SEC_CAPS;
		*a2 = 0;
		*a3 = 0;
		return SMC_RETURN_OK;
	case SMC_GET_SHM_CONFIG:
		*a1 = 0;
		*a2 = 0;
		*a3 = 0;
		return SMC_RETURN_ENOTAVAIL;
	case SMC_GET_THREAD_COUNT:
		*a1 = 1;
		*a2 = 0;
		*a3 = 0;
		return SMC_RETURN_OK;
	default:
		return -EINVAL;
	}
}

static int rustee_krecv(struct socket *s, void *buf, size_t n)
{
	size_t got = 0;

	while (got < n) {
		struct kvec iov = {
			.iov_base = (u8 *)buf + got,
			.iov_len = n - got,
		};
		struct msghdr msg = { .msg_flags = MSG_WAITALL };
		int r = kernel_recvmsg(s, &msg, &iov, 1, n - got, MSG_WAITALL);

		if (r <= 0)
			return r ? r : -EPIPE;
		got += r;
	}
	return 0;
}

static int rustee_ksend(struct socket *s, const void *buf, size_t n)
{
	size_t put = 0;

	while (put < n) {
		struct kvec iov = {
			.iov_base = (void *)((const u8 *)buf + put),
			.iov_len = n - put,
		};
		struct msghdr msg = {};
		int r = kernel_sendmsg(s, &msg, &iov, 1, n - put);

		if (r <= 0)
			return r ? r : -EPIPE;
		put += r;
	}
	return 0;
}

static int rustee_vsock_ensure(struct rustee_priv *p)
{
	struct socket *s;
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = RUSTEE_VSOCK_CID,
		.svm_port = RUSTEE_VSOCK_PORT,
	};
	int err;

	if (p->vsock)
		return 0;
	err = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &s);
	if (err)
		return err;
	err = kernel_connect(s, (struct sockaddr *)&addr, sizeof(addr), 0);
	if (err) {
		sock_release(s);
		return err;
	}
	p->vsock = s;
	return 0;
}

static void rustee_frame_encode(u8 out[RUSTEE_CALLFRAME_LEN], const u64 r[8])
{
	int i;

	for (i = 0; i < 8; i++)
		put_unaligned_le64(r[i], out + i * 8);
}

static void rustee_frame_decode(u64 r[8], const u8 in[RUSTEE_CALLFRAME_LEN])
{
	int i;

	for (i = 0; i < 8; i++)
		r[i] = get_unaligned_le64(in + i * 8);
}

/*
 * One outstanding yielding call. Writes ENTER, reads until COMPLETE.
 * KIND_RPC is not answered here (supplicant owns RPC).
 */
static int rustee_yield(struct rustee_priv *p, const u64 frame_r[8], u32 bounce_len)
{
	u8 hdr[RUSTEE_PDU_HDR_LEN];
	u8 arg[RUSTEE_CALLFRAME_LEN];
	u32 kind, seq, arg_len, blen;
	u64 out_r[8];
	int err;

	if (p->yielding)
		return -EBUSY;
	if (bounce_len > RUSTEE_BOUNCE_SIZE)
		return -EINVAL;
	err = rustee_vsock_ensure(p);
	if (err)
		return err;

	p->yielding = true;
	put_unaligned_le32(RUSTEE_KIND_ENTER, hdr + 0);
	put_unaligned_le32(p->seq, hdr + 4);
	put_unaligned_le32(RUSTEE_CALLFRAME_LEN, hdr + 8);
	put_unaligned_le32(bounce_len, hdr + 12);
	p->seq++;
	rustee_frame_encode(arg, frame_r);

	err = rustee_ksend(p->vsock, hdr, RUSTEE_PDU_HDR_LEN);
	if (!err)
		err = rustee_ksend(p->vsock, arg, RUSTEE_CALLFRAME_LEN);
	if (!err && bounce_len)
		err = rustee_ksend(p->vsock, p->bounce, bounce_len);
	if (err)
		goto out;

	for (;;) {
		err = rustee_krecv(p->vsock, hdr, RUSTEE_PDU_HDR_LEN);
		if (err)
			goto out;
		kind = get_unaligned_le32(hdr + 0);
		seq = get_unaligned_le32(hdr + 4);
		arg_len = get_unaligned_le32(hdr + 8);
		blen = get_unaligned_le32(hdr + 12);
		(void)seq;
		if (arg_len != RUSTEE_CALLFRAME_LEN || blen > RUSTEE_BOUNCE_SIZE) {
			err = -EPROTO;
			goto out;
		}
		err = rustee_krecv(p->vsock, arg, RUSTEE_CALLFRAME_LEN);
		if (err)
			goto out;
		if (blen) {
			err = rustee_krecv(p->vsock, p->bounce, blen);
			if (err)
				goto out;
		}
		rustee_frame_decode(out_r, arg);
		(void)out_r;
		if (kind == RUSTEE_KIND_COMPLETE) {
			err = 0;
			goto out;
		}
		if (kind == RUSTEE_KIND_RPC) {
			/* teepriv RPC later; userspace StreamTransport answers this. */
			err = -EOPNOTSUPP;
			goto out;
		}
		err = -EPROTO;
		goto out;
	}
out:
	p->yielding = false;
	return err;
}

static int rustee_get_version(struct tee_context *ctx,
			      struct tee_ioctl_version_data *vers)
{
	(void)ctx;
	vers->impl_id = TEE_IMPL_ID_OPTEE;
	vers->impl_caps = TEE_OPTEE_CAP_TZ;
	vers->gen_caps = TEE_GEN_CAP_GP | TEE_GEN_CAP_REG_MEM;
	return 0;
}

static int rustee_open(struct tee_context *ctx)
{
	struct rustee_priv *p;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	p->bounce = vzalloc(RUSTEE_BOUNCE_SIZE);
	if (!p->bounce) {
		kfree(p);
		return -ENOMEM;
	}
	p->seq = 1;
	ctx->data = p;
	return 0;
}

static void rustee_release(struct tee_context *ctx)
{
	struct rustee_priv *p = ctx->data;

	if (!p)
		return;
	if (p->vsock)
		sock_release(p->vsock);
	vfree(p->bounce);
	kfree(p);
}

static void rustee_fail(struct tee_ioctl_open_session_arg *oarg,
		       struct tee_ioctl_invoke_arg *iarg, u32 ret)
{
	if (oarg) {
		oarg->ret = ret;
		oarg->ret_origin = TEEC_ORIGIN_COMMS;
	}
	if (iarg) {
		iarg->ret = ret;
		iarg->ret_origin = TEEC_ORIGIN_COMMS;
	}
}

static int rustee_call(struct rustee_priv *p, u64 cookie, u32 bounce_len,
		       struct tee_ioctl_open_session_arg *oarg,
		       struct tee_ioctl_invoke_arg *iarg)
{
	u64 r[8] = { 0 };
	int err;

	if (!p) {
		rustee_fail(oarg, iarg, TEEC_ERROR_NOT_IMPLEMENTED);
		return 0;
	}
	r[0] = SMC_CALL_WITH_ARG;
	r[1] = cookie >> 32;
	r[2] = cookie & 0xffffffffull;
	err = rustee_yield(p, r, bounce_len);
	if (err == -EBUSY) {
		rustee_fail(oarg, iarg, TEEC_ERROR_BUSY);
		return 0;
	}
	if (err) {
		rustee_fail(oarg, iarg, TEEC_ERROR_COMMUNICATION);
		return 0;
	}
	if (oarg) {
		oarg->ret = 0;
		oarg->ret_origin = 3;
	}
	if (iarg) {
		iarg->ret = 0;
		iarg->ret_origin = 3;
	}
	return 0;
}

static int rustee_open_session(struct tee_context *ctx,
			       struct tee_ioctl_open_session_arg *arg,
			       struct tee_param *param)
{
	(void)param;
	/*
	 * Host copies user params into bounce, builds optee_msg_arg at an
	 * 8-aligned cookie, sets CallFrame a0=CALL_WITH_ARG a1:a2=cookie,
	 * vsocks ENTER (arg_len=64) + bounce_len covering MSG+memrefs.
	 * One outstanding yielding call. MSG packing from tee_param is
	 * still incremental; the vsock ENTER/COMPLETE path is live.
	 */
	return rustee_call(ctx->data, 8, 256, arg, NULL);
}

static int rustee_close_session(struct tee_context *ctx, u32 session)
{
	u64 r[8] = { 0 };
	struct rustee_priv *p = ctx->data;

	(void)session;
	if (!p)
		return 0;
	r[0] = SMC_CALL_WITH_ARG;
	(void)rustee_yield(p, r, 64);
	return 0;
}

static int rustee_invoke(struct tee_context *ctx,
			 struct tee_ioctl_invoke_arg *arg,
			 struct tee_param *param)
{
	(void)param;
	return rustee_call(ctx->data, 8, 256, NULL, arg);
}

static int rustee_cancel(struct tee_context *ctx, u32 cancel_id, u32 session)
{
	(void)ctx;
	(void)cancel_id;
	(void)session;
	return 0;
}

static const struct tee_driver_ops rustee_ops = {
	.get_version = rustee_get_version,
	.open = rustee_open,
	.release = rustee_release,
	.open_session = rustee_open_session,
	.close_session = rustee_close_session,
	.invoke_func = rustee_invoke,
	.cancel_req = rustee_cancel,
};

static const struct tee_desc rustee_desc = {
	.flags = 0,
	.name = "rustee-virt",
	.ops = &rustee_ops,
	.owner = THIS_MODULE,
};

static struct tee_device *rustee_teedev;

static int __init rustee_virt_init(void)
{
	u32 a1 = 0, a2 = 0, a3 = 0;

	if (rustee_answer_fast(SMC_CALLS_UID, &a1, &a2, &a3) != rustee_calls_uid[0])
		return -EINVAL;
	rustee_teedev = tee_device_alloc(&rustee_desc, NULL, NULL, NULL);
	if (IS_ERR(rustee_teedev))
		return PTR_ERR(rustee_teedev);
	if (tee_device_register(rustee_teedev)) {
		tee_device_put(rustee_teedev);
		return -ENODEV;
	}
	pr_info("rustee-virt: bounce %u vsock %u:%u CallFrame %u (not TCB)\n",
		RUSTEE_BOUNCE_SIZE, RUSTEE_VSOCK_CID, RUSTEE_VSOCK_PORT,
		RUSTEE_CALLFRAME_LEN);
	return 0;
}

static void __exit rustee_virt_exit(void)
{
	if (rustee_teedev)
		tee_device_unregister(rustee_teedev);
}

module_init(rustee_virt_init);
module_exit(rustee_virt_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RUSTEE virt tee transport (vsock + bounce)");
MODULE_AUTHOR("RUSTEE Client/REE");
