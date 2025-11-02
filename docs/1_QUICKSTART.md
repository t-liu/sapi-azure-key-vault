# Quick Start Guide

Get up and running with the Azure Key Vault Properties API in 5 minutes.

## Prerequisites Checklist

- [ ] Python 3.12+ installed
- [ ] Azure Functions Core Tools v4 installed
- [ ] Azure CLI installed and logged in (`az login`)
- [ ] Access to an Azure Key Vault
- [ ] Azure subscription

## Step 1: Install Dependencies (2 minutes)

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

## Step 2: Configure Settings (1 minute)

Copy the template and update with your values:

```bash
cp config/local.settings.template.json config/local.settings.json
```

Edit `config/local.settings.json`:
```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "AZURE_KEY_VAULT_URL": "https://YOUR-KEYVAULT.vault.azure.net/",
    "VALID_CLIENT_ID": "test-client-id",
    "VALID_CLIENT_SECRET": "test-client-secret",
    "LOG_LEVEL": "INFO"
  }
}
```

## Step 3: Authenticate with Azure (1 minute)

```bash
# Login to Azure (for DefaultAzureCredential)
az login
```

## Step 4: Start the Function (30 seconds)

```bash
func start
```

Expected output:
```
Azure Functions Core Tools
Core Tools Version:       4.x
Function Runtime Version: 4.x

Functions:
  get_properties: [GET] http://localhost:7071/api/v1/properties
  post_properties: [POST] http://localhost:7071/api/v1/properties
  put_properties: [PUT] http://localhost:7071/api/v1/properties
  delete_properties: [DELETE] http://localhost:7071/api/v1/properties
```

## Step 5: Test the API (30 seconds)

### Test with curl

```bash
# Create a property
curl -X POST "http://localhost:7071/api/v1/properties" \
  -H "client_id: test-client-id" \
  -H "client_secret: test-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "properties": [
      {
        "environment": "qa",
        "key": "test-app",
        "properties": {
          "test.property": "hello-world"
        }
      }
    ]
  }'

# Retrieve the property
curl -X GET "http://localhost:7071/api/v1/properties?env=qa&key=test-app" \
  -H "client_id: test-client-id" \
  -H "client_secret: test-client-secret"
```

### Test with VS Code REST Client

1. Install "REST Client" extension in VS Code
2. Open `api-examples.http`
3. Update the variables at the top
4. Click "Send Request" above any request

## Common Issues & Solutions

### Issue: "Authentication configuration error"
**Solution**: Ensure `VALID_CLIENT_ID` and `VALID_CLIENT_SECRET` are set in `local.settings.json`

### Issue: "Key Vault access denied"
**Solution**: 
```bash
# Get your identity
az ad signed-in-user show --query id -o tsv

# Grant access (replace values)
az keyvault set-policy \
  --name YOUR-KEYVAULT \
  --object-id YOUR-OBJECT-ID \
  --secret-permissions get list set delete
```

### Issue: Module not found errors
**Solution**: Ensure virtual environment is activated and dependencies are installed
```bash
source venv/bin/activate
pip install -r requirements.txt
```

## Project Structure

```
sapi-azure-key-vault/
├── app/                         # Application code
│   ├── function_app.py          # Main Azure Function (HTTP triggers)
│   ├── keyvault_service.py      # Service layer for Key Vault
│   └── models.py                # Pydantic validation models
├── tests/                       # Test suites (unit, integration, smoke)
├── docs/                        # Documentation
│   ├── QUICKSTART.md           # This file
│   ├── CICD.md                 # CI/CD documentation
│   └── PROJECT_SUMMARY.md      # Project overview
├── scripts/                     # Utility scripts
│   └── deploy.sh               # Deployment script
├── config/                      # Configuration files
│   └── local.settings.template.json
├── examples/                    # Example JSON files
├── .github/workflows/           # CI/CD pipeline
├── requirements.txt             # Python dependencies
├── host.json                    # Azure Functions configuration
└── README.md                    # Full documentation
```

## Next Steps

1. **Read Full Documentation**: Check `README.md` for complete API documentation
2. **Test All Endpoints**: Use `api-examples.http` to test all operations
3. **Deploy to Azure**: Follow deployment instructions in `README.md`
4. **Configure Monitoring**: Set up Application Insights for production

## Production Deployment (Quick)

```bash
# Make script executable
chmod +x scripts/deploy.sh

# Deploy
./scripts/deploy.sh <function-app-name> <resource-group> <key-vault-name>
```

## API Endpoints Summary

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/v1/properties?env={env}&key={key}` | Retrieve properties |
| POST | `/api/v1/properties` | Create/update properties |
| PUT | `/api/v1/properties` | Update properties |
| DELETE | `/api/v1/properties?env={env}&key={key}` | Delete properties |

**All endpoints require**:
- Header: `client_id`
- Header: `client_secret`

## Support

- Full Documentation: `README.md`
- API Examples: `api-examples.http`
- Azure Functions Docs: https://docs.microsoft.com/azure/azure-functions/
- Azure Key Vault Docs: https://docs.microsoft.com/azure/key-vault/

---

**Ready to go!** 🚀

If you encounter issues, check the logs output in your terminal where `func start` is running.

