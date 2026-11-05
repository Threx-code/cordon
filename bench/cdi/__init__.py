"""CDI learning pipeline, B/E/F side (modelling + learning team).

B: featureset -- a FeatureSet from an existing scan row (reuse, not a new analyser).
E: miss        -- a DetectionMiss from a confirmed false negative.
F: candidate   -- the candidate factory (rule packs / model updates), able to reject.

Schemas and the two-gate factory-eligibility rule live in ``schemas``.
"""

from . import candidate, featureset, miss, schemas

__all__ = ["candidate", "featureset", "miss", "schemas"]
