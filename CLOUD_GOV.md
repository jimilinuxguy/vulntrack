# Cloud.gov SQLite demonstration

The Cloud Foundry manifest uses an ephemeral SQLite database and automatically seeds **fictional** tenants, CVEs, KEVs, findings, and assignments. No RDS connection or service binding is required.

```sh
git checkout feat/cloud-gov-cloud-foundry
git pull origin feat/cloud-gov-cloud-foundry
cf push vulntrack-sandbox -f manifest.yml
cf app vulntrack-sandbox
curl -i https://vulntrack-sandbox.app.cloud.gov/health
```

The manifest sets `VULNTRACK_CLOUD_FOUNDRY=true`, `VULNTRACK_DEMO_MODE=true`, and `VULNTRACK_DEV_AUTH=false`. SQLite is stored at `/tmp/vulntrack-demo.db`. Data can disappear on restart, restage, redeploy, or instance replacement. Use one instance and never store real findings or sensitive data in this demo.

**OIDC is still required to use the dashboard.** Configure a reachable identity provider, such as PIV-Proxy:

```sh
cf set-env vulntrack-sandbox VULNTRACK_OIDC_ISSUER https://YOUR-ISSUER
cf set-env vulntrack-sandbox VULNTRACK_OIDC_JWKS_URL https://YOUR-ISSUER/jwks
cf set-env vulntrack-sandbox VULNTRACK_OIDC_AUDIENCE vulntrack
cf set-env vulntrack-sandbox VULNTRACK_OIDC_CLIENT_ID YOUR-CLIENT-ID
cf set-env vulntrack-sandbox VULNTRACK_OIDC_AUTHORIZE_URL https://YOUR-ISSUER/authorize
cf set-env vulntrack-sandbox VULNTRACK_OIDC_TOKEN_URL https://YOUR-ISSUER/token
cf restart vulntrack-sandbox
```

Register `https://vulntrack-sandbox.app.cloud.gov/` as an allowed OIDC redirect. Users need the `vulntrack-admin` role claim or explicit tenant membership to view demo data. The fictional seed memberships do not automatically grant access to real users.

For production, disable `VULNTRACK_DEMO_MODE`, restore the managed PostgreSQL service binding, resolve network access, and add proper migrations. Do not enable development authentication in Cloud Foundry.
