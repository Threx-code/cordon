# The Bitbucket pipe image. Built at release from the same hash pin as every other template, so
# the pipe runs the scanner that was published and nothing else.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
COPY action/requirements.txt /tmp/cordon-requirements.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps \
      -r /tmp/cordon-requirements.txt \
 && rm /tmp/cordon-requirements.txt
COPY ci/bitbucket/pipe.sh /pipe.sh
USER 65534:65534
ENTRYPOINT ["/bin/sh", "/pipe.sh"]
