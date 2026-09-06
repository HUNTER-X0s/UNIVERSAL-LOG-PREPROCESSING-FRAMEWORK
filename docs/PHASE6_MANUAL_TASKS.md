# ULPF Phase 6 Manual Tasks (Operational Deployment)

The following tasks represent real-world physical and operational actions required for physical deployment outside the software codebase:

1. **Hardware & Perimeter Appliance Provisioning**: Provision physical servers and storage appliances for air-gapped deployment.
2. **TLS Certificate Provisioning**: Generate and install internal PKI TLS certificates for HTTPS/mTLS endpoints.
3. **Firewall & Network Ingestion Rules**: Configure physical firewall port forwarding (syslog UDP/TCP 514) to the ULPF ingestion listeners.
4. **Physical Air-Gap USB/Data Diode Transport**: Transfer signed air-gap deployment bundle to isolated network.
