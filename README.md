# android-device-integrity

## Server Application Deployment

This project includes two Google App Engine (GAE) applications located in the `server/` directory:
- `key_attestation`
- `play_integrity`

These applications are automatically deployed to Google Cloud via a GitHub Actions workflow.

### Deployment Trigger

The deployment workflow is triggered when changes are pushed to the `deploy/gae` branch AND there are modifications within the `server/` directory or its subdirectories.

### Required GitHub Secrets

For the deployment workflow to authenticate with Google Cloud and deploy the applications, the following secrets must be configured in your GitHub repository settings (`Settings` > `Secrets and variables` > `Actions`):

- **`GCP_PROJECT_ID`**: Your Google Cloud Project ID.
- **`WORKLOAD_IDENTITY_PROVIDER`**: The full identifier of the Workload Identity Provider configured in your Google Cloud project for GitHub Actions.
  - Example: `projects/123456789012/locations/global/workloadIdentityPools/my-github-pool/providers/my-github-provider`
- **`KEY_ATTESTATION_SA_EMAIL`**: The email address of the Google Cloud Service Account used to deploy the `key_attestation` application. This service account must have the necessary permissions (e.g., App Engine Deployer, Service Account User, Storage Object Admin) and be linked to the Workload Identity Provider.
  - Example: `key-attestation-deployer@<GCP_PROJECT_ID>.iam.gserviceaccount.com`
- **`PLAY_INTEGRITY_SA_EMAIL`**: The email address of the Google Cloud Service Account used to deploy the `play_integrity` application. This service account also requires appropriate permissions and linkage to the Workload Identity Provider.
  - Example: `play-integrity-deployer@<GCP_PROJECT_ID>.iam.gserviceaccount.com`

### Manual Deployment

If you need to deploy manually or for a different environment, you can use the `gcloud` CLI:

```bash
# For Key Attestation app
gcloud app deploy server/key_attestation/app.yaml --project <YOUR_GCP_PROJECT_ID> --service-account <KEY_ATTESTATION_SA_EMAIL>

# For Play Integrity app
gcloud app deploy server/play_integrity/app.yaml --project <YOUR_GCP_PROJECT_ID> --service-account <PLAY_INTEGRITY_SA_EMAIL>
```

Ensure your local `gcloud` is authenticated with appropriate permissions if deploying manually.
