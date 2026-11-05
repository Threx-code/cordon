"""Layered configuration: the settings (`settings`), how a file is read into them (`parser`), the
layers resolved under the organisation's ceiling (`resolver`), and the policy (`policy`).

`Config` is the package's public name, importable from the package itself as it was before the
package was split.
"""

from cordon_scanner.foundation.config.settings import Config

__all__ = ["Config"]
