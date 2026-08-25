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
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include <linux/vmalloc.h>

#define RUSTEE_BOUNCE_SIZE	(16u * 1024u * 1024u)
#define RUSTEE_VSOCK_CID	3u
#define RUSTEE_VSOCK_PORT	7007u
#define RUSTEE_CALLFRAME_LEN	64u
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

static int rustee_open_session(struct tee_context *ctx,
			       struct tee_ioctl_open_session_arg *arg,
			       struct tee_param *param)
{
	(void)ctx;
	(void)param;
	/*
	 * Host copies user params into bounce, builds optee_msg_arg at an
	 * 8-aligned cookie, sets CallFrame a0=CALL_WITH_ARG a1:a2=cookie,
	 * vsocks ENTER (arg_len=64) + bounce_len covering MSG+memrefs.
	 * One outstanding yielding call. Implemented incrementally; bind
	 * path and fast SMCCC are live so libteec can probe the device.
	 */
	arg->ret = 0xFFFF0009;
	arg->ret_origin = 0x00000002;
	return 0;
}

static int rustee_close_session(struct tee_context *ctx, u32 session)
{
	(void)ctx;
	(void)session;
	return 0;
}

static int rustee_invoke(struct tee_context *ctx,
			 struct tee_ioctl_invoke_arg *arg,
			 struct tee_param *param)
{
	(void)ctx;
	(void)param;
	arg->ret = 0xFFFF0009;
	arg->ret_origin = 0x00000002;
	return 0;
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
