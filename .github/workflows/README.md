# GitHub Actions Workflows

## Quick Setup

### Step 1: Configure GitHub Secrets

Navigate to: **Settings → Secrets and variables → Actions**

Add the following secrets:

#### Azure Credentials (Staging)
```
Name: AZURE_CREDENTIALS_STAGING
Value: 
{
  "clientId": "your-sp-client-id",
  "clientSecret": "your-sp-client-secret",
  "subscriptionId": "your-subscription-id",
  "tenantId": "your-tenant-id"
}
```

#### Azure Credentials (Production)
```
Name: AZURE_CREDENTIALS_PROD
Value: (same format as staging, different service principal)
```

#### Test Credentials
```
Name: TEST_API_CLIENT_ID
Value: test-client-id

Name: TEST_API_CLIENT_SECRET
Value: test-client-secret
```

#### Production Credentials
```
Name: PROD_API_CLIENT_ID
Value: prod-client-id

Name: PROD_API_CLIENT_SECRET
Value: prod-client-secret
```

#### Azure Resources
```
Name: AZURE_RESOURCE_GROUP
Value: your-resource-group-name

Name: APP_INSIGHTS_NAME
Value: your-app-insights-name
```

#### Notifications
```
Name: TEAMS_WEBHOOK_URL
Value: https://outlook.office.com/webhook/YOUR/WEBHOOK/URL
```

**Setting Up MS Teams Webhook**:
1. In your MS Teams channel, click the "..." menu → "Connectors"
2. Search for "Incoming Webhook" and click "Configure"
3. Provide a name (e.g., "Azure Function Deployments") and upload an icon (optional)
4. Copy the webhook URL
5. Add it to GitHub repository secrets as `TEAMS_WEBHOOK_URL`

**Notifications sent to Teams**:
- ✅ Successful production deployments (green card)
- ❌ Failed deployments with rollback alerts (red card)
- 🚨 Critical rollback events during validation failures (red card)

### Step 2: Configure Environments

Navigate to: **Settings → Environments**

Create three environments:

#### 1. Staging Environment
- Name: `staging`
- Protection rules: None
- Secrets: None (uses repository secrets)

#### 2. Production Approval Environment
- Name: `production-approval`
- Protection rules:
  - ✅ Required reviewers: 1-2 people
  - ✅ Wait timer: 0 minutes (optional: add delay)
- Purpose: Manual approval gate

#### 3. Production Environment
- Name: `production`
- Protection rules:
  - ✅ Required reviewers: 2+ people
  - ✅ Deployment branches: Only `main` branch
- Secrets: None (uses repository secrets)

### Step 3: Update Workflow Variables

Edit `.github/workflows/deploy.yml`:

```yaml
env:
  PYTHON_VERSION: '3.11'
  AZURE_FUNCTIONAPP_NAME_STAGING: 'your-staging-function-app-name'
  AZURE_FUNCTIONAPP_NAME_PROD: 'your-prod-function-app-name'
```

### Step 4: Create Azure Service Principals

```bash
# For Staging
az ad sp create-for-rbac --name "github-actions-staging" \
  --role contributor \
  --scopes /subscriptions/{subscription-id}/resourceGroups/{staging-rg} \
  --sdk-auth

# For Production
az ad sp create-for-rbac --name "github-actions-prod" \
  --role contributor \
  --scopes /subscriptions/{subscription-id}/resourceGroups/{prod-rg} \
  --sdk-auth
```

Copy the JSON output to the respective `AZURE_CREDENTIALS_*` secrets.

## Workflow File

**File**: `.github/workflows/deploy.yml`

**Stages**:
1. ✅ Lint & Static Analysis
2. ✅ Unit Tests
3. ✅ Build & Package
4. ✅ Deploy to Staging
5. ✅ Integration Tests
6. ✅ Smoke Tests
7. ⏸️ Manual Approval
8. 🚀 Production Deployment
9. 🔍 Post-Deploy Monitoring & Rollback

## Testing the Workflow

### Test on Pull Request

```bash
git checkout -b test-cicd
git commit --allow-empty -m "Test CI/CD pipeline"
git push origin test-cicd
# Create PR to main
```

### Test Staging Deployment

```bash
git checkout develop
git commit --allow-empty -m "Test staging deployment"
git push origin develop
```

### Test Production Deployment

```bash
git checkout main
git merge develop
git push origin main
# Approve in GitHub UI when prompted
```

## Monitoring Deployments

### Via GitHub UI

1. Go to **Actions** tab
2. Click on the running workflow
3. Monitor each stage in real-time
4. View logs by clicking on each step

### Via Notifications

- MS Teams: Real-time notifications with rich cards
  - Green cards for successful deployments
  - Red cards for failures and rollbacks
  - Links to workflow runs and deployments
- Email: GitHub will email you on failures
- GitHub Issues: Auto-created on rollback

## Common Issues

### Issue: "Azure CLI login failed"

**Cause**: Invalid service principal credentials

**Fix**:
1. Verify `AZURE_CREDENTIALS_*` secrets are correct
2. Ensure service principal has contributor role
3. Check subscription ID is correct

### Issue: "Required reviewers not set"

**Cause**: Environment protection rules not configured

**Fix**:
1. Go to Settings → Environments
2. Select `production-approval`
3. Add required reviewers
4. Save changes

### Issue: "Tests failing in CI but pass locally"

**Cause**: Environment variables not set

**Fix**:
1. Check workflow file for env vars
2. Add missing secrets to GitHub
3. Verify secret names match workflow

## Customization

### Change Python Version

```yaml
env:
  PYTHON_VERSION: '3.10'  # Change here
```

### Adjust Test Timeouts

```yaml
- name: Run Unit Tests
  run: pytest tests/unit/ -v --timeout=60  # Add timeout
```

### Modify Approval Requirements

```yaml
# In GitHub UI: Settings → Environments → production-approval
# Adjust required reviewers, wait time, etc.
```

### Add More Stages

Add new job to `deploy.yml`:

```yaml
custom-validation:
  name: Custom Validation
  runs-on: ubuntu-latest
  needs: smoke-tests-staging
  steps:
    - name: Custom check
      run: echo "Custom validation"
```

## Best Practices

1. ✅ Always test changes in staging first
2. ✅ Monitor Application Insights during deployment
3. ✅ Have rollback plan ready
4. ✅ Communicate deployment windows to team
5. ✅ Review all test results before approval

## Support

- **Pipeline Issues**: Check workflow logs in GitHub Actions
- **Azure Issues**: Check Azure Portal → Function App → Deployment Center
- **Test Failures**: Review test reports in artifacts

---

**Need Help?** Check the full documentation in `CICD.md`

