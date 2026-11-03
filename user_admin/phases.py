"""Deterministic progress for multiple execution phases of one native intent."""

from django.db.models import Case, IntegerField, Value, When

from .models import Operation


def latest_phase(target, generation=None):
    phases = Operation.objects.filter(target=target)
    if generation is not None:
        phases = phases.filter(generation=generation)
    return (
        phases.annotate(
            phase_order=Case(
                When(action=Operation.Action.CREATE, then=Value(0)),
                When(action=Operation.Action.BIND, then=Value(1)),
                When(action=Operation.Action.ENABLE, then=Value(2)),
                When(action=Operation.Action.BLOCK, then=Value(3)),
                default=Value(-1),
                output_field=IntegerField(),
            )
        )
        .order_by("-generation", "-phase_order")
        .first()
    )
