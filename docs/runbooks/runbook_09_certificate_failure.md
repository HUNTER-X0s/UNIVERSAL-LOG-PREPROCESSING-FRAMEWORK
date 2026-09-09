# RUNBOOK-09: mTLS Certificate or Token Expiry

## 1. Trigger & Condition
**Condition:** Internal service-to-service communication fails due to expired certificate or bad signature.  
**Trigger:** SSL handshake failure; HTTP 401/403 unauthorized on internal API routes.  

---

## 2. Diagnosis & Root Cause Identification
1. Inspect certificate expiration date (`openssl x509 -enddate -noout -in <cert>`).
2. Inspect signing CA trust chain.
3. Verify system clock synchronization (`chronyc tracking`).

---

## 3. Mitigation & Resolution Steps
1. Rotate expired certificate with offline CA-signed bundle.
2. Distribute updated certificate to worker nodes.
3. Gracefully reload service daemons (`systemctl reload ulpf-*`).

---

## 4. Verification & Health Restoration
Test mTLS mutual handshake with `curl --cert <cert> --key <key> https://localhost:8443/health`.

---

## 5. Rollback & Post-Incident Safeguards
Fallback to pre-staged emergency certificate if CA infrastructure is temporarily unreachable.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
