Deployment Strategy

This project provides a PII (Personally Identifiable Information) detection and redaction service.
The goal is to prevent sensitive data leaks in real-time while also scanning existing datasets.

Where It Runs

The detector can be deployed in multiple ways, depending on your use case:

Sidecar container (Primary)
Runs alongside your application pods. The app calls the detector locally (localhost) before writing to storage or responding to users.
→ Lowest latency, easy to scale, minimal code changes.

API Gateway / Ingress plugin (Secondary)
Runs at the edge (Kong, NGINX, Envoy, etc.). Intercepts requests and responses for centralised protection.
→ Single control point, no app refactor needed.

DaemonSet or Scheduled Job (Tertiary)
Periodic jobs to scan databases, CSV files, or object storage for historical PII.
→ Useful for catching existing leaks and cleaning up legacy data.

Why This Approach?

Scalability: Sidecars scale with app pods, central service can autoscale, batch jobs run on demand.

Low latency: Local loopback calls for sidecars keep response times fast.

Cost-effective: You only run what you need—sidecars for critical services, a central service for shared logic, jobs for bulk scans.

Easy to integrate: Minimal code changes. Drop in a sidecar, or just add a plugin at the gateway.

Quick Start

Containerise the detector code (e.g. with FastAPI/Flask wrapper).

Deploy as one of:

A Sidecar in your Kubernetes pod spec.

A Central service behind a ClusterIP and call it via http://pii-redactor:8080/redact.

A Gateway plugin for ingress/egress traffic.

A Job/DaemonSet for bulk file scanning.

Mount rules/config as a ConfigMap so you can update detection rules without rebuilding images.

Monitor with Prometheus/Grafana for metrics like detection count, latency, and errors.
