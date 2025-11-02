# CI/CD Pipeline Documentation

## Overview

This project uses a comprehensive GitHub Actions workflow for continuous integration and deployment. The pipeline implements industry best practices including automated testing, security scanning, blue-green deployments, and automatic rollbacks.

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    CONTINUOUS INTEGRATION                        │
├─────────────────────────────────────────────────────────────────┤
│ 1. Lint & Static Analysis                                       │
│    ├─ Black (formatting)                                        │
│    ├─ Flake8 (linting)                                          │
│    ├─ Pylint (code quality)                                     │
│    ├─ MyPy (type checking)                                      │
│    └─ Bandit (security)                                         │
├─────────────────────────────────────────────────────────────────┤
│ 2. Unit Tests                                                   │
│    ├─ pytest with coverage                                      │
│    └─ Upload coverage reports                                   │
├─────────────────────────────────────────────────────────────────┤
│ 3. Build & Package                                              │
│    ├─ Create deployment artifact                               │
│    └─ Upload to GitHub                                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                 CONTINUOUS DEPLOYMENT - STAGING                  │
├─────────────────────────────────────────────────────────────────┤
│ 4. Deploy to Staging                                            │
│    └─ Deploy to staging slot                                    │
├─────────────────────────────────────────────────────────────────┤
│ 5. Integration Tests                                            │
│    └─ Full API integration tests                               │
├─────────────────────────────────────────────────────────────────┤
│ 6. Smoke Tests                                                  │
│    ├─ Quick validation tests                                    │
│    └─ Health check monitoring                                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                CONTINUOUS DEPLOYMENT - PRODUCTION                │
├─────────────────────────────────────────────────────────────────┤
│ 7. Manual Approval Gate                                         │
│    └─ Requires manual approval in GitHub                        │
├─────────────────────────────────────────────────────────────────┤
│ 8. Production Deployment                                        │
│    ├─ Deploy to production staging slot                        │
│    ├─ Pre-swap validation                                       │
│    └─ Blue-green slot swap                                      │
├─────────────────────────────────────────────────────────────────┤
│ 9. Post-Deploy Monitoring                                       │
│    ├─ Production smoke tests                                    │
│    ├─ Health check monitoring (2 minutes)                      │
│    ├─ Application Insights metrics                             │
│    └─ AUTOMATIC ROLLBACK on failure                            │
└─────────────────────────────────────────────────────────────────┘
```

## Stage Details

### Stage 1: Lint & Static Analysis

**Purpose**: Ensure code quality and security before testing

**Tools Used**:
- **Black**: Code formatting validation
- **Flake8**: PEP 8 compliance and code style
- **Pylint**: Advanced code quality checks
- **MyPy**: Static type checking
- **Bandit**: Security vulnerability scanning

**Success Criteria**: All linters pass (some are informational only)

### Stage 2: Unit Tests

**Purpose**: Validate individual components in isolation

**Coverage**:
- Function-level tests
- Model validation
- Service layer logic
- Mock external dependencies

**Output**:
- Code coverage report (HTML & XML)
- Upload to Codecov
- Minimum 80% coverage recommended

### Stage 3: Build & Package

**Purpose**: Create deployment artifact

**Process**:
1. Install dependencies
2. Create `.python_packages` directory
3. Package all required files
4. Upload artifact for deployment

**Artifact Contents**:
- `app/` directory (all application code)
- `host.json`
- `requirements.txt`
- `.python_packages/`

### Stage 4: Deploy to Staging

**Purpose**: Deploy to staging environment for validation

**Process**:
1. Download build artifact
2. Authenticate with Azure
3. Deploy to staging slot
4. Wait for deployment stabilization

**Slot**: `staging` slot of staging function app

### Stage 5: Integration Tests

**Purpose**: Validate API behavior in real environment

**Tests**:
- Full CRUD operations
- Authentication flows
- Data persistence
- Error handling

**Environment**: Runs against staging deployment

### Stage 6: Smoke Tests

**Purpose**: Quick validation of critical functionality

**Tests**:
- API reachability
- Authentication
- Response format
- Response time (<3s)
- Error handling

**Duration**: ~30 seconds

### Stage 7: Manual Approval

**Purpose**: Human verification before production

**Requirements**:
- Only runs for `main` branch
- Requires GitHub environment approval
- Reviewers should check:
  - Staging metrics
  - Test results
  - Recent changes

### Stage 8: Production Deployment

**Purpose**: Deploy to production with zero downtime

**Process**:
1. Deploy to production's staging slot
2. Warm up the slot
3. Run pre-swap validation
4. **Swap slots** (blue-green deployment)
5. Wait for swap completion

**Zero Downtime**: Achieved through slot swapping

### Stage 9: Post-Deploy Monitoring & Rollback

**Purpose**: Validate production deployment and rollback if needed

**Monitoring**:
- Production smoke tests
- 2-minute health check monitoring
- Application Insights metrics
- Error rate analysis

**Automatic Rollback Triggers**:
- Failed smoke tests
- Failed health checks
- Error rate spike
- Any validation failure

**Rollback Process**:
1. Detect failure
2. Swap slots back to previous version
3. Send notifications (MS Teams, GitHub issue)
4. Log rollback event

## GitHub Secrets Required

### Azure Credentials

```yaml
AZURE_CREDENTIALS_STAGING:
  {
    "clientId": "...",
    "clientSecret": "...",
    "subscriptionId": "...",
    "tenantId": "..."
  }

AZURE_CREDENTIALS_PROD:
  {
    "clientId": "...",
    "clientSecret": "...",
    "subscriptionId": "...",
    "tenantId": "..."
  }
```

### API Credentials

```yaml
TEST_CLIENT_ID: "test-client-id"
TEST_CLIENT_SECRET: "test-client-secret"
PROD_CLIENT_ID: "prod-client-id"
PROD_CLIENT_SECRET: "prod-client-secret"
```

### Azure Resources

```yaml
AZURE_RESOURCE_GROUP: "your-resource-group"
APP_INSIGHTS_NAME: "your-app-insights-name"
```

### Notifications

```yaml
TEAMS_WEBHOOK_URL: "https://outlook.office.com/webhook/..."
```

**Setting Up MS Teams Webhook**:
1. In your MS Teams channel, click the "..." menu → "Connectors"
2. Search for "Incoming Webhook" and click "Configure"
3. Provide a name (e.g., "Azure Function Deployments") and upload an icon (optional)
4. Copy the webhook URL
5. Add it to GitHub repository secrets as `TEAMS_WEBHOOK_URL`

## Environment Configuration

### Staging Environment

**Name**: `staging`

**Protection Rules**: None (automatic deployment)

**Purpose**: Pre-production validation

### Production Approval Environment

**Name**: `production-approval`

**Protection Rules**:
- Required reviewers: 1+
- Timeout: 30 days

**Purpose**: Manual gate before production

### Production Environment

**Name**: `production`

**Protection Rules**:
- Required reviewers: 2+
- Deployment branch: `main` only

**Purpose**: Live production deployment

## Triggering the Pipeline

### Automatic Triggers

```yaml
# Push to main or develop
git push origin main
git push origin develop

# Pull request to main
Create PR → main
```

### Manual Trigger

```yaml
# Via GitHub UI
Actions → Deploy → Run workflow
  - Select environment: staging | production
```

## Monitoring & Notifications

### Success Notifications

- ✅ MS Teams notification with deployment details (green card)
  - Environment, Function App, Repository info
  - Commit SHA, Author, Branch
  - Link to deployed application
- GitHub commit status updated

### Failure Notifications

- ❌ MS Teams alert with error details (red card)
  - Rollback status and failure reason
  - Link to GitHub workflow run
- GitHub issue automatically created
- Email to repository watchers

### Rollback Notifications

- 🚨 Critical MS Teams alert (red card)
  - Deployment failure and rollback notification
  - Deployment details and commit information
  - Link to workflow run for investigation
- GitHub issue with "rollback" label
- Detailed error logs attached

## Local Testing

### Run Unit Tests Locally

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all unit tests
pytest tests/unit/ -v --cov

# Run specific test file
pytest tests/unit/test_models.py -v
```

### Run Integration Tests Locally

```bash
# Set environment variables
export API_BASE_URL=http://localhost:7071
export API_CLIENT_ID=test-client-id
export API_CLIENT_SECRET=test-client-secret

# Run integration tests
pytest tests/integration/ -v
```

### Run Smoke Tests Locally

```bash
# Quick smoke tests
pytest tests/smoke/ -v

# Health check
python tests/smoke/health_check.py

# Continuous monitoring
python tests/smoke/health_check.py --monitor --duration=60
```

### Run Linters Locally

```bash
# Format check
black --check .

# Linting
flake8 .

# Type checking
mypy app/

# Security scan
bandit -r app/
```

## Troubleshooting

### Pipeline Fails at Lint Stage

**Problem**: Code formatting or style issues

**Solution**:
```bash
# Auto-fix formatting
black .

# Check linting issues
flake8 .
```

### Pipeline Fails at Unit Tests

**Problem**: Test failures or low coverage

**Solution**:
```bash
# Run tests locally to see failures
pytest tests/unit/ -v -s

# Run with coverage report
pytest tests/unit/ --cov --cov-report=html
# Open htmlcov/index.html
```

### Deployment Fails at Staging

**Problem**: Azure deployment issues

**Solution**:
1. Check Azure credentials are correct
2. Verify resource group and function app exist
3. Check Azure portal for deployment logs

### Integration Tests Fail

**Problem**: API not responding correctly

**Solution**:
1. Check staging deployment logs
2. Verify environment variables are set
3. Test API manually with curl
4. Check Application Insights for errors

### Automatic Rollback Triggered

**Problem**: Production validation failed

**Solution**:
1. Check rollback GitHub issue for details
2. Review Application Insights metrics
3. Compare staging vs production behavior
4. Fix issues and redeploy

## Best Practices

### Before Merging to Main

1. ✅ All tests pass locally
2. ✅ Code reviewed by peers
3. ✅ Staging deployment successful
4. ✅ Integration tests pass
5. ✅ Documentation updated

### During Deployment

1. 👀 Monitor pipeline progress
2. 📊 Check staging metrics before approval
3. 🚨 Be ready to rollback if needed
4. 📝 Document any issues

### After Deployment

1. 📈 Monitor Application Insights
2. ✅ Verify smoke tests pass
3. 🔍 Check error rates
4. 👥 Notify stakeholders

## Performance Metrics

**Target SLAs**:
- Pipeline duration: < 15 minutes
- Unit tests: < 2 minutes
- Deployment: < 3 minutes
- Integration tests: < 5 minutes
- Response time: < 500ms (p95)
- Availability: 99.9%

## Security Considerations

1. **Secrets Management**: All secrets in GitHub Secrets
2. **Least Privilege**: Service principals with minimal permissions
3. **Security Scanning**: Bandit runs on every commit
4. **Dependency Updates**: Regular security updates
5. **Audit Logging**: All deployments logged

## Rollback Procedures

### Automatic Rollback

Triggers automatically when:
- Health checks fail
- Error rate > threshold
- Smoke tests fail

### Manual Rollback

```bash
# Via Azure CLI
az functionapp deployment slot swap \
  --resource-group <rg> \
  --name <function-app> \
  --slot staging \
  --target-slot production
```

## Continuous Improvement

### Metrics to Track

- Deployment frequency
- Lead time for changes
- Mean time to recovery (MTTR)
- Change failure rate
- Test coverage

### Regular Reviews

- Weekly: Review failed deployments
- Monthly: Pipeline performance analysis
- Quarterly: Update dependencies and tools

---

**Version**: 1.0.0  
**Last Updated**: November 2025  
**Owner**: Platform Engineering Team

