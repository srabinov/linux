/*
 * Copyright (c) 2017, Mellanox Technologies inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <rdma/uverbs_std_types.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <linux/bug.h>
#include <linux/file.h>
#include "rdma_core.h"
#include "uverbs.h"

static int uverbs_free_ah(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_ah *ah = uobject->object;
	struct ib_pd *pd = ah->pd;
	struct ib_uobject *pduobj =
		ib_ctx_uobj_find(&pd->uobject, uobject->context);

	WARN_ONCE(!pduobj, "pd uobj not found in context!\n");
	if (pduobj)
		atomic_dec(&pduobj->obj_usecnt);

	return rdma_destroy_ah(ah);
}

static int uverbs_free_flow(struct ib_uobject *uobject,
			    enum rdma_remove_reason why)
{
	return ib_destroy_flow((struct ib_flow *)uobject->object);
}

static int uverbs_free_mw(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_mw *mw = uobject->object;
	struct ib_pd *pd = mw->pd;
	struct ib_uobject *pduobj =
		ib_ctx_uobj_find(&pd->uobject, uobject->context);

	WARN_ONCE(!pduobj, "pd uobj not found in context!\n");
	if (pduobj)
		atomic_dec(&pduobj->obj_usecnt);

	return uverbs_dealloc_mw((struct ib_mw *)uobject->object);
}

static int uverbs_free_qp(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_qp *qp = uobject->object;
	struct ib_uqp_object *uqp =
		container_of(uobject, struct ib_uqp_object, uevent.uobject);
	int ret;
	struct ib_pd *pd = qp->pd;
	struct ib_uobject *pduobj =
		ib_ctx_uobj_find(&pd->uobject, uobject->context);

	WARN_ONCE(!pduobj, "pd uobj not found in context!\n");
	if (pduobj)
		atomic_dec(&pduobj->obj_usecnt);

	if (why == RDMA_REMOVE_DESTROY) {
		if (!list_empty(&uqp->mcast_list))
			return -EBUSY;
	} else if (qp == qp->real_qp) {
		ib_uverbs_detach_umcast(qp, uqp);
	}

	ret = ib_destroy_qp(qp);
	if (ret && why == RDMA_REMOVE_DESTROY)
		return ret;

	if (uqp->uxrcd)
		atomic_dec(&uqp->uxrcd->refcnt);

	ib_uverbs_release_uevent(uobject->context->ufile, &uqp->uevent);
	return ret;
}

static int uverbs_free_rwq_ind_tbl(struct ib_uobject *uobject,
				   enum rdma_remove_reason why)
{
	struct ib_rwq_ind_table *rwq_ind_tbl = uobject->object;
	struct ib_wq **ind_tbl = rwq_ind_tbl->ind_tbl;
	int ret;

	ret = ib_destroy_rwq_ind_table(rwq_ind_tbl);
	if (!ret || why != RDMA_REMOVE_DESTROY)
		kfree(ind_tbl);
	return ret;
}

static int uverbs_free_wq(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_wq *wq = uobject->object;
	struct ib_uwq_object *uwq =
		container_of(uobject, struct ib_uwq_object, uevent.uobject);
	int ret;
	struct ib_pd *pd = wq->pd;
	struct ib_uobject *pduobj =
		ib_ctx_uobj_find(&pd->uobject, uobject->context);

	WARN_ONCE(!pduobj, "pd uobj not found in context!\n");
	if (pduobj)
		atomic_dec(&pduobj->obj_usecnt);

	ret = ib_destroy_wq(wq);
	if (!ret || why != RDMA_REMOVE_DESTROY)
		ib_uverbs_release_uevent(uobject->context->ufile, &uwq->uevent);
	return ret;
}

static int uverbs_free_srq(struct ib_uobject *uobject,
			   enum rdma_remove_reason why)
{
	struct ib_srq *srq = uobject->object;
	struct ib_uevent_object *uevent =
		container_of(uobject, struct ib_uevent_object, uobject);
	enum ib_srq_type  srq_type = srq->srq_type;
	int ret;

	ret = ib_destroy_srq(srq);

	if (ret && why == RDMA_REMOVE_DESTROY)
		return ret;

	if (srq_type == IB_SRQT_XRC) {
		struct ib_usrq_object *us =
			container_of(uevent, struct ib_usrq_object, uevent);

		atomic_dec(&us->uxrcd->refcnt);
	}

	ib_uverbs_release_uevent(uobject->context->ufile, uevent);
	return ret;
}

static int uverbs_free_cq(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_cq *cq = uobject->object;
	struct ib_uverbs_event_queue *ev_queue = cq->cq_context;
	struct ib_ucq_object *ucq =
		container_of(uobject, struct ib_ucq_object, uobject);
	int ret;

	ret = ib_destroy_cq(cq);
	if (!ret || why != RDMA_REMOVE_DESTROY)
		ib_uverbs_release_ucq(uobject->context->ufile, ev_queue ?
				      container_of(ev_queue,
						   struct ib_uverbs_completion_event_file,
						   ev_queue) : NULL,
				      ucq);
	return ret;
}

static int uverbs_free_mr(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_mr *mr = uobject->object;
	struct ib_pd *pd = mr->pd;
	struct ib_uobject *pduobj =
		ib_ctx_uobj_find(&pd->uobject, uobject->context);

	WARN_ONCE(!pduobj, "pd uobj not found in context!\n");
	if (pduobj)
		atomic_dec(&pduobj->obj_usecnt);

	return ib_dereg_mr((struct ib_mr *)uobject->object);
}

static int uverbs_free_xrcd(struct ib_uobject *uobject,
			    enum rdma_remove_reason why)
{
	struct ib_xrcd *xrcd = uobject->object;
	struct ib_uxrcd_object *uxrcd =
		container_of(uobject, struct ib_uxrcd_object, uobject);
	int ret;

	mutex_lock(&uobject->context->ufile->device->xrcd_tree_mutex);
	if (why == RDMA_REMOVE_DESTROY && atomic_read(&uxrcd->refcnt))
		ret = -EBUSY;
	else
		ret = ib_uverbs_dealloc_xrcd(uobject->context->ufile->device,
					     xrcd, why);
	mutex_unlock(&uobject->context->ufile->device->xrcd_tree_mutex);

	return ret;
}

/* must be called with device shobj_lock spinlock held! */
void uverbs_release_pd(struct kref *kref)
{
	struct ib_pd *pd = container_of(kref, struct ib_pd, ref);
	int usecnt = atomic_read(&pd->usecnt);
	struct ib_device *device = pd->device;

	WARN_ONCE(usecnt, "pd leak!! usecnt != 0! usecnt %d\n", usecnt);

	/* ib pd kref should call us when last pd uobj want to release
	 * the pd object. we expect zero usecnt here but if it is not
	 * we cannot dealloc the ib pd!
	 */
	if (usecnt) {
		spin_unlock(&device->shobj_lock);
		return;
	}

	/* we are about to delete this shared ib_pd.
	 * make sure no one can share it by handle..
	 */
	idr_remove(&device->pd_idr, pd->handle);

	spin_unlock(&device->shobj_lock);

	/* no one can share the pd and no context / ib_xxx need it */
	ib_dealloc_pd(pd);
}

static int uverbs_free_pd(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_ucontext	*context = uobject->context;
	struct ib_device	*device = context->device;
	struct ib_pd		*pd = uobject->object;
	int			 ret;

	/* if kref_put call uverbs_release_pd the spin lock
	 * will be freed in the function. otherwise, here.
	 */
	spin_lock(&device->shobj_lock);

	/* make sure no other context currently using this pd */
	ret = kref_put(&pd->ref, uverbs_release_pd);

	if (!ret)
		spin_unlock(&device->shobj_lock);

	return 0;
}

static int uverbs_hot_unplug_completion_event_file(struct ib_uobject_file *uobj_file,
						   enum rdma_remove_reason why)
{
	struct ib_uverbs_completion_event_file *comp_event_file =
		container_of(uobj_file, struct ib_uverbs_completion_event_file,
			     uobj_file);
	struct ib_uverbs_event_queue *event_queue = &comp_event_file->ev_queue;

	spin_lock_irq(&event_queue->lock);
	event_queue->is_closed = 1;
	spin_unlock_irq(&event_queue->lock);

	if (why == RDMA_REMOVE_DRIVER_REMOVE) {
		wake_up_interruptible(&event_queue->poll_wait);
		kill_fasync(&event_queue->async_queue, SIGIO, POLL_IN);
	}
	return 0;
};

const struct uverbs_obj_fd_type uverbs_type_attrs_comp_channel = {
	.type = UVERBS_TYPE_ALLOC_FD(sizeof(struct ib_uverbs_completion_event_file), 0),
	.context_closed = uverbs_hot_unplug_completion_event_file,
	.fops = &uverbs_event_fops,
	.name = "[infinibandevent]",
	.flags = O_RDONLY,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_cq = {
	.type = UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_ucq_object), 0),
	.destroy_object = uverbs_free_cq,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_qp = {
	.type = UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uqp_object), 0),
	.destroy_object = uverbs_free_qp,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_mw = {
	.type = UVERBS_TYPE_ALLOC_IDR(0),
	.destroy_object = uverbs_free_mw,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_mr = {
	/* 1 is used in order to free the MR after all the MWs */
	.type = UVERBS_TYPE_ALLOC_IDR(1),
	.destroy_object = uverbs_free_mr,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_srq = {
	.type = UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_usrq_object), 0),
	.destroy_object = uverbs_free_srq,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_ah = {
	.type = UVERBS_TYPE_ALLOC_IDR(0),
	.destroy_object = uverbs_free_ah,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_flow = {
	.type = UVERBS_TYPE_ALLOC_IDR(0),
	.destroy_object = uverbs_free_flow,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_wq = {
	.type = UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uwq_object), 0),
	.destroy_object = uverbs_free_wq,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_rwq_ind_table = {
	.type = UVERBS_TYPE_ALLOC_IDR(0),
	.destroy_object = uverbs_free_rwq_ind_tbl,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_xrcd = {
	.type = UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uxrcd_object), 0),
	.destroy_object = uverbs_free_xrcd,
};

const struct uverbs_obj_idr_type uverbs_type_attrs_pd = {
	/* 2 is used in order to free the PD after MRs */
	.type = UVERBS_TYPE_ALLOC_IDR(2),
	.destroy_object = uverbs_free_pd,
};
