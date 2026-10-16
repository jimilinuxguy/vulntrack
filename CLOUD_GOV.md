# Deploy VulnTrack to Cloud.gov sandbox

This is a disposable demonstration deployment, not a production authorization to process agency vulnerability data.

## Prerequisites
Install the Cloud Foundry CLI and obtain Cloud.gov sandbox access. Have a reachable OIDC identity provider (including PIV-Proxy if deployed separately) and register the final app route as an OIDC callback.

## Provision and deploy
```sh
cf login -a api.fr.cloud.gov --sso
cf orgs
cf target -o YOUR_SANDBOX_ORG -s YOUR_SPACE
cf marketplace
```

Select a PostgreSQL service and plan actually available to your space. For example, if offered:
```sh
cf create-service aws-rds micro-psql vulntrack-db
cf service vulntrack-db
```

Wait for successful provisioning. The manifest binds service `vulntrack-db`. Cloud Foundry provides credentials through `VCAP_SERVICES`. The application refuses to start without a PostgreSQL binding and uses TLS to connect.

```sh
cf push --no-start
cf set-env vulntrack-sandbox VULNTRACK_OIDC_ISSUER https://YOUR-ISSUER
cf set-env vulntrack-sandbox VULNTRACK_OIDC_JWKS_URL https://YOUR-ISSUER/jwks
cf set-env vulntrack-sandbox VULNTRACK_OIDC_AUDIENCE vulntrack
cf set-env vulntrack-sandbox VULNTRACK_OIDC_CLIENT_ID YOUR-PUBLIC-CLIENT-ID
cf set-env vulntrack-sandbox VULNTRACK_OIDC_AUTHORIZE_URL https://YOUR-ISSUER/authorize
cf set-env vulntrack-sandbox VULNTRACK_OIDC_TOKEN_URL https://YOUR-ISSUER/token
cf start vulntrack-sandbox
cf app vulntrack-sandbox
cf logs vulntrack-sandbox --recent
```

Replace placeholder URLs with actual identity-provider metadata. The browser redirect URI must be registered as `https://YOUR-APP-ROUTE/`. The application must receive OIDC access tokens accepted by its issuer/JWKS/audience validation. `/health` checks web availability only.

## Safety
- Never enable `VULNTRACK_DEV_AUTH` on Cloud Foundry; startup rejects it.
- The local demo seed command requires development auth and is deliberately unavailable on Cloud Foundry. Do not bypass the restriction.
- Keep secrets out of Git and avoid pasting `cf env` or `VCAP_SERVICES` output into tickets.
- Database schema currently uses `create_all`; production requires migrations, review of tenant isolation and access controls, and an approved deployment boundary.
- The manifest runs one instance for sandbox evaluation, not high availability.
- `cf push` deploys Python buildpack assets; Docker Compose remains local-only.
