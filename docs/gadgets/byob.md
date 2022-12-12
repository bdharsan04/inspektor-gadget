---
# Code generated by 'make generate-documentation'. DO NOT EDIT.
title: Gadget byob
---

byob runs eBPF program in a OCI registry.

### Example CR

```yaml
apiVersion: gadget.kinvolk.io/v1alpha1
kind: Trace
metadata:
  name: byob
  namespace: gadget
spec:
  node: minikube
  gadget: byob
  filter:
    namespace: default
  runMode: Manual
  outputMode: Stream
  parameters:
    # OCI Image containing the ELF module
    ociImage: "ghcr.io/solo-io/bumblebee/tcpconnect:0.0.11"
    # ELF module compressed with zlib and encoded in base64
    progContent: ""
```

### Operations


#### start

Start byob gadget

```bash
$ kubectl annotate -n gadget trace/byob \
    gadget.kinvolk.io/operation=start
```
#### stop

Stop byob gadget

```bash
$ kubectl annotate -n gadget trace/byob \
    gadget.kinvolk.io/operation=stop
```

### Output Modes

* Stream