"""Cordon's model server: a signed model bundle, served over HTTPS to scanners in the same
organisation (`cordon-scanner scan --model URL`) or behind Cordon Cloud.

    bundle    loads a bundle only if its signature and every file's digest verify
    scoring   validates cordon.model/v1 requests and scores them
    http      the HTTP interface: authentication, TLS, limits, access log
    health    the container's liveness probe
"""
