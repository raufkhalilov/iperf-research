#!/bin/sh
set -eu
# Use only an already available image; no image is downloaded implicitly.
image=${CAPTURE_IMAGE:-r.1440.space/sls/devops/images/sls-builder:v2.18.0}
exec docker run --pull=never --rm --network host --cap-drop ALL --cap-add NET_RAW \
  --security-opt no-new-privileges --read-only --user 0 \
  --entrypoint /usr/bin/tcpdump \
  -v /usr/bin/tcpdump:/usr/bin/tcpdump:ro \
  -v /lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:ro \
  -v /lib64:/lib64:ro "$image" -Z root "$@"
