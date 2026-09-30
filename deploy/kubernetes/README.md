# Kubernetes

```bash
kubectl apply -f namespace.yaml
kubectl -n security-graph create secret generic secgraph-secrets \
  --from-literal=SECGRAPH_DATABASE_URL='postgresql+psycopg://secgraph:<password>@<host>:5432/secgraph' \
  --from-literal=SECGRAPH_JWT_SECRET="$(openssl rand -hex 48)" \
  --from-literal=SECGRAPH_METRICS_TOKEN="$(openssl rand -hex 24)"
# edit kustomization.yaml (image registry and tag) and ingress.yaml (host name, TLS secret)
kubectl apply -k .
kubectl -n security-graph rollout status deploy/secgraph-api
kubectl -n security-graph exec deploy/secgraph-api -- secgraph doctor
```

| File | What it is |
|---|---|
| `namespace.yaml` | namespace with the restricted Pod Security Standard enforced |
| `configmap.yaml` | non-secret settings |
| `secret.example.yaml` | template for the secret — create the real one from your secret manager |
| `migrate-job.yaml` | applies migrations; the name carries the version, so each release is a new Job |
| `api.yaml` | API Deployment (2 replicas), Service, PodDisruptionBudget |
| `worker.yaml` | worker Deployment |
| `networkpolicy.yaml` | default-deny ingress; the API reachable from the ingress controller, monitoring and labelled client namespaces |
| `ingress.yaml` | example for ingress-nginx with TLS |
| `postgres-dev.yaml` | single-pod PostgreSQL for trials only — not in the kustomization, not for production |

These manifests validate against the Kubernetes 1.30 API schemas (`kubeconform -strict`) and the
image they run is exercised by CI under the same security context with Docker Compose. They have not
been applied to a live cluster by the authors: expect to adjust the ingress class, the
NetworkPolicy namespace labels and the resource requests to your platform.

Operations — upgrades, backups, monitoring, sizing — are in
[docs/OPERATIONS.md](../../docs/OPERATIONS.md).
