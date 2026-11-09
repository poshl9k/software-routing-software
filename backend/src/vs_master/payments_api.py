"""Redacted, read-only administrator view of Stars ledger and renewal tickets."""
from datetime import timedelta

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from .admin_api import aware, get_db, now
from .auth import current_admin
from .models import DeviceOp, PaymentReceipt, StarsFulfillment, StarsOrder, StarsPaymentEvent

router = APIRouter(prefix='/api/master-admin/payments', dependencies=[Depends(current_admin)])


@router.get('/reconciliation')
def reconciliation(request: Request, limit: int = Query(default=50, ge=1, le=100),
                   before_id: int | None = Query(default=None, ge=1),
                   db: Session = Depends(get_db)):
    """Read one SQLite snapshot; never disclose charge IDs, payer IDs or payload hashes."""
    if db.get_bind().dialect.name == 'sqlite':
        db.execute(text('BEGIN'))
    timestamp = now(request)
    query = select(StarsOrder).order_by(StarsOrder.id.desc())
    if before_id is not None:
        query = query.where(StarsOrder.id < before_id)
    rows = list(db.scalars(query.limit(limit + 1)))
    has_more = len(rows) > limit
    rows = rows[:limit]
    op_rows = db.execute(select(StarsFulfillment.order_id, StarsFulfillment.node_id,
                                DeviceOp.status, DeviceOp.detail)
                         .join(DeviceOp, DeviceOp.id == StarsFulfillment.op_id)
                         .where(StarsFulfillment.order_id.in_(row.id for row in rows))
                         .order_by(StarsFulfillment.order_id, StarsFulfillment.node_id)).all() if rows else []
    operations = {row.id: [] for row in rows}
    for order_id, node_id, status, detail in op_rows:
        operations[order_id].append({'node_id': node_id, 'status': status,
                                     'detail': 'renewed' if detail == 'renewed' else None})
    events = {status: count for status, count in db.execute(
        select(StarsPaymentEvent.status, func.count()).group_by(StarsPaymentEvent.status))}
    receipt_without_event = select(StarsPaymentEvent.fingerprint).where(
        StarsPaymentEvent.telegram_charge_id == PaymentReceipt.telegram_charge_id).exists()
    summary = {
        'orders': db.scalar(select(func.count(StarsOrder.id))) or 0,
        'receipts': db.scalar(select(func.count(PaymentReceipt.telegram_charge_id))) or 0,
        'granted_events': events.get('granted', 0),
        'review_events': events.get('review', 0),
        'unmatched_events': events.get('unmatched', 0),
        'orphan_receipts': db.scalar(select(func.count(PaymentReceipt.telegram_charge_id))
                                     .where(~receipt_without_event)) or 0,
        'pending_renewals': db.scalar(select(func.count(StarsOrder.id)).where(
            StarsOrder.state == 'paid', StarsOrder.fulfillment_status == 'pending')) or 0,
        'review_orders': db.scalar(select(func.count(StarsOrder.id)).where(or_(
            StarsOrder.state == 'review', StarsOrder.fulfillment_status == 'review'))) or 0,
    }

    def order_view(row):
        attention = None
        if row.state == 'review' or row.fulfillment_status == 'review':
            attention = 'payment.review'
        elif row.state == 'sending' and row.created_at <= timestamp - timedelta(minutes=5):
            attention = 'invoice.ack_unknown'
        elif (row.state == 'paid' and row.fulfillment_status == 'pending'
              and (row.paid_at is None or row.paid_at <= timestamp - timedelta(minutes=5))):
            attention = 'renewal.overdue'
        return {'id': row.id, 'account_id': row.account_id, 'state': row.state,
                'currency': row.currency, 'amount': row.amount,
                'created_at': aware(row.created_at), 'expires_at': aware(row.expires_at),
                'paid_at': aware(row.paid_at), 'granted_expires_at': aware(row.granted_expires_at),
                'fulfillment_status': row.fulfillment_status, 'attention': attention,
                'operations': operations[row.id]}

    return {'summary': summary, 'orders': [order_view(row) for row in rows],
            'next_before_id': rows[-1].id if has_more else None}
