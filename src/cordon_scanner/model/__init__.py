"""Cordon's own detection model: the features read from a package on the scanning machine, and the
client that has a Cordon model server score them (Cordon Cloud, or one inside the organisation).

    features   what the model reads -- numbers and hashed identifiers, never source
    client     the `cordon.model/v1` exchange with a model server
"""
