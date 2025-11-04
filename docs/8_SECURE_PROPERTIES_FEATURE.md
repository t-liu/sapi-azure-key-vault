# Secure Properties Feature

**Date**: November 2025  
**Feature**: Shared Secure Properties Management  
**Status**: ✅ **PRODUCTION READY**

## Overview

The Secure Properties feature enables centralized management of sensitive credentials that can be shared across multiple applications. This eliminates duplication and simplifies secrets rotation.

### Problem Statement

Previously, if multiple applications needed the same credentials (e.g., CRM API credentials), each application would store its own copy:

**Before (Without Secure Properties)**:
```
app1 → stores crm.client.id, crm.client.secret
app2 → stores crm.client.id, crm.client.secret
app3 → stores crm.client.id, crm.client.secret
```

**Issues**:
- **Duplication**: Same credentials stored multiple times
- **Rotation nightmare**: Must update all apps when credentials change
- **Inconsistency risk**: Apps might have different versions of credentials
- **Increased attack surface**: More places credentials can leak

### Solution: Secure Properties

Secure properties are stored once and referenced by multiple applications:

**After (With Secure Properties)**:
```
secure-property: crm-secrets → contains crm.client.id, crm.client.secret
app1 → references "crm-secrets" via secure.properties key
app2 → references "crm-secrets" via secure.properties key
app3 → references "crm-secrets" via secure.properties key
```

**Benefits**:
- ✅ **Single source of truth**: Credentials stored once
- ✅ **Easy rotation**: Update once, all apps get new credentials
- ✅ **Consistency**: All apps always have the same credentials
- ✅ **Reduced attack surface**: Fewer copies to protect

---

## Architecture

### Storage Structure

**Regular Properties**:
```
Azure Key Vault Secret: {env}--{app_key}--{property_key}
Example: qa--my-app--api-endpoint
```

**Secure Properties**:
```
Azure Key Vault Secret: {env}--{secure_key}--{property_key}
Example: qa--crm-secrets--crm.client.id
```

**Same underlying storage mechanism**, but different semantic meaning:
- **Regular properties**: App-specific configuration
- **Secure properties**: Shared secrets referenced by multiple apps

### Reference Pattern

Applications reference secure properties using a special key:

#### Single Reference

```json
{
  "environment": "qa",
  "key": "my-application",
  "properties": {
    "app.name": "My Application",
    "api.endpoint": "https://api.example.com",
    "secure.properties": "crm-secrets"  ← Reference to secure properties
  }
}
```

**Usage Flow**:
1. Get regular properties for `qa/my-application`
2. See `secure.properties` key with value `crm-secrets`
3. Make a second call to GET `/v1/properties/secure?env=qa&key=crm-secrets`
4. Combine both sets of properties

#### Multiple References (Comma-Delimited)

Applications can reference multiple secure properties:

```json
{
  "environment": "prod",
  "key": "enterprise-app",
  "properties": {
    "app.name": "Enterprise Application",
    "api.endpoint": "https://api.example.com",
    "secure.properties": "crm-secrets,db-creds,api-keys"  ← Multiple references
  }
}
```

**Client-Side Implementation**:
```python
# 1. Fetch application properties
app_response = requests.get(
    f"{API_BASE_URL}/v1/properties",
    headers=auth_headers,
    params={"env": "prod", "key": "enterprise-app"}
)
app_props = app_response.json()["responses"][0]["properties"]

# 2. Check for secure property references
if "secure.properties" in app_props:
    secure_refs = app_props["secure.properties"]
    
    # 3. Split comma-delimited string and fetch each
    all_secrets = {}
    for secure_key in secure_refs.split(","):
        secure_key = secure_key.strip()  # Remove whitespace
        
        # Fetch secure property
        secure_response = requests.get(
            f"{API_BASE_URL}/v1/properties/secure",
            headers=auth_headers,
            params={"env": "prod", "key": secure_key}
        )
        
        # Merge secrets
        secrets = secure_response.json()["responses"][0]["properties"]
        all_secrets.update(secrets)
    
    # 4. Combine application config with all secrets
    final_config = {**app_props, **all_secrets}
    
    # Remove reference key (optional)
    del final_config["secure.properties"]
    
    return final_config
```

**Note**: The API stores `secure.properties` as a plain string. Parsing comma-delimited values and making multiple GET calls is the **client application's responsibility**. This design:
- ✅ Keeps the API simple and stateless
- ✅ Gives clients control over parallelization
- ✅ Enables client-side caching strategies
- ✅ Maintains flexibility in delimiter choice

---

## API Endpoints

### Base URL
```
/v1/properties/secure
```

### Authentication
Same as regular properties endpoints:
- `client_id`: Your client ID
- `client_secret`: Your client secret
- `X-Correlation-ID`: Optional correlation ID for request tracking

---

### GET - Retrieve Secure Properties

Retrieve shared secure properties.

**Request:**
```http
GET /v1/properties/secure?env=qa&key=crm-secrets
Headers:
  client_id: your-client-id
  client_secret: your-client-secret
```

**Response:**
```json
{
  "responses": [
    {
      "env": "qa",
      "key": "crm-secrets",
      "properties": {
        "crm.client.id": "abc123",
        "crm.client.secret": "secret456"
      }
    }
  ]
}
```

**Status Codes:**
- `200` - Success
- `401` - Authentication failed
- `400` - Missing parameters
- `500` - Internal error

---

### POST - Create Secure Properties

Create new shared secure properties (returns 201).

**Request:**
```http
POST /v1/properties/secure
Headers:
  client_id: your-client-id
  client_secret: your-client-secret
Content-Type: application/json

{
  "properties": [
    {
      "environment": "qa",
      "key": "crm-secrets",
      "properties": {
        "crm.client.id": "abc123",
        "crm.client.secret": "secret456"
      }
    }
  ]
}
```

**Response:**
```json
{
  "responses": [
    {
      "environment": "qa",
      "key": "crm-secrets",
      "code": 200,
      "message": "Secure Properties Posted Successfully"
    }
  ]
}
```

**Status Codes:**
- `201` - Created successfully
- `401` - Authentication failed
- `400` - Validation error
- `500` - Internal error

---

### PUT - Update Secure Properties

Update existing shared secure properties (returns 200).

**Request:**
```http
PUT /v1/properties/secure
Headers:
  client_id: your-client-id
  client_secret: your-client-secret
Content-Type: application/json

{
  "properties": [
    {
      "environment": "qa",
      "key": "crm-secrets",
      "properties": {
        "crm.client.id": "new-abc123",
        "crm.client.secret": "new-secret456"
      }
    }
  ]
}
```

**Response:**
```json
{
  "responses": [
    {
      "environment": "qa",
      "key": "crm-secrets",
      "code": 200,
      "message": "Secure Properties Updated Successfully"
    }
  ]
}
```

**Status Codes:**
- `200` - Updated successfully
- `401` - Authentication failed
- `400` - Validation error
- `500` - Internal error

---

### DELETE - Remove Secure Properties

Delete shared secure properties.

**Request:**
```http
DELETE /v1/properties/secure?env=qa&key=crm-secrets
Headers:
  client_id: your-client-id
  client_secret: your-client-secret
```

**Response:**
```json
{
  "message": "Successfully deleted secure properties for qa/crm-secrets",
  "env": "qa",
  "key": "crm-secrets",
  "deleted_count": 2
}
```

**Status Codes:**
- `200` - Deleted successfully
- `401` - Authentication failed
- `400` - Missing parameters
- `500` - Internal error

---

## Usage Examples

### Example 1: CRM Credentials Shared Across Services

**Step 1: Create secure properties**
```bash
curl -X POST "https://your-function-app.azurewebsites.net/api/v1/properties/secure" \
  -H "client_id: your-client-id" \
  -H "client_secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "properties": [{
      "environment": "prod",
      "key": "salesforce-creds",
      "properties": {
        "sf.client.id": "3MVG9...",
        "sf.client.secret": "1234567...",
        "sf.username": "api@company.com",
        "sf.security.token": "abc123..."
      }
    }]
  }'
```

**Step 2: Reference in multiple applications**

Application 1 (Order Service):
```bash
curl -X POST "https://your-function-app.azurewebsites.net/api/v1/properties" \
  -H "client_id: your-client-id" \
  -H "client_secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "properties": [{
      "environment": "prod",
      "key": "order-service",
      "properties": {
        "service.name": "Order Service",
        "secure.properties": "salesforce-creds"
      }
    }]
  }'
```

Application 2 (Inventory Service):
```bash
curl -X POST "https://your-function-app.azurewebsites.net/api/v1/properties" \
  -H "client_id: your-client-id" \
  -H "client_secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "properties": [{
      "environment": "prod",
      "key": "inventory-service",
      "properties": {
        "service.name": "Inventory Service",
        "secure.properties": "salesforce-creds"
      }
    }]
  }'
```

**Step 3: Rotate credentials (affects all services)**
```bash
curl -X PUT "https://your-function-app.azurewebsites.net/api/v1/properties/secure" \
  -H "client_id: your-client-id" \
  -H "client_secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "properties": [{
      "environment": "prod",
      "key": "salesforce-creds",
      "properties": {
        "sf.client.id": "NEW_3MVG9...",
        "sf.client.secret": "NEW_1234567...",
        "sf.username": "api@company.com",
        "sf.security.token": "NEW_abc123..."
      }
    }]
  }'
```

✅ **Both order-service and inventory-service now get the new credentials automatically!**

---

### Example 2: Database Connection Strings

**Secure Properties (Database)**:
```json
{
  "environment": "prod",
  "key": "postgres-main-db",
  "properties": {
    "db.host": "prod-db.postgres.database.azure.com",
    "db.port": "5432",
    "db.username": "dbadmin",
    "db.password": "super-secret-password",
    "db.ssl.mode": "require"
  }
}
```

**Application Properties (Multiple Services)**:
```json
// Service 1
{
  "environment": "prod",
  "key": "user-service",
  "properties": {
    "service.port": "8080",
    "secure.properties": "postgres-main-db"
  }
}

// Service 2
{
  "environment": "prod",
  "key": "auth-service",
  "properties": {
    "service.port": "8081",
    "secure.properties": "postgres-main-db"
  }
}
```

---

## Best Practices

### 1. **Naming Conventions**

Use descriptive names for secure properties:
- ✅ **Good**: `salesforce-prod-creds`, `postgres-main-db`, `redis-cache-cluster`
- ❌ **Bad**: `secrets1`, `creds`, `db`

### 2. **Granularity**

Group related credentials together:
- ✅ **Good**: All Salesforce credentials in one secure property
- ❌ **Bad**: Each credential as separate secure property

### 3. **Environment Isolation**

Always separate credentials by environment:
```
qa/salesforce-creds      → QA credentials
staging/salesforce-creds → Staging credentials
prod/salesforce-creds    → Production credentials
```

### 4. **Rotation Strategy**

1. Update secure properties with new credentials
2. Applications pick up new values on next retrieval (cache TTL: 5 minutes)
3. Monitor for errors during transition
4. Old credentials can be deactivated after grace period

### 5. **Access Control**

Secure properties use the same authentication as regular properties:
- Only authenticated clients can access
- Same rate limiting applies (100 req/60s per client)
- All operations logged with correlation IDs

---

## Security Considerations

### Same Security as Regular Properties

Secure properties have **identical security** to regular properties:
- ✅ Timing-attack resistant authentication
- ✅ Rate limiting (100 requests per 60 seconds)
- ✅ IP-based audit logging
- ✅ Generic error messages (no information leakage)
- ✅ Correlation ID tracking

### Additional Considerations

1. **Principle of Least Privilege**
   - Only apps that need specific credentials should reference them
   - Don't create one mega secure-property with all secrets

2. **Audit Trail**
   - All access logged with timestamps and IPs
   - Correlation IDs enable request tracing

3. **Rotation**
   - Plan regular rotation schedule
   - Test rotation in lower environments first
   - Monitor applications during rotation

---

## Performance

### Caching

Secure properties benefit from the same 5-minute cache as regular properties:
- **First request**: ~50-200ms (Key Vault call)
- **Cached requests**: ~5-10ms (in-memory)
- **Cache invalidation**: Automatic on updates/deletes

### Best Practices

1. **Batch Operations**: Update multiple secure properties in one request
2. **Cache Warmup**: Pre-fetch after deployment
3. **Monitoring**: Track cache hit rates in Application Insights

---

## Testing

### Unit Tests

- ✅ 4 new unit tests added for secure endpoints
- ✅ Total: 77 unit tests (was 73)

### Integration Tests

- ✅ Full lifecycle test (POST → GET → PUT → DELETE)
- ✅ Shared reference test (multiple apps → one secure property)

### Smoke Tests

- ✅ Health checks include secure endpoints
- ✅ End-to-end validation in staging

---

## Migration Guide

### Migrating Existing Duplicated Credentials

**Step 1: Identify Duplicates**
```bash
# Find all apps with CRM credentials
az keyvault secret list --vault-name your-vault | grep "crm.client"
```

**Step 2: Create Secure Property**
```bash
# Create centralized secure property
POST /v1/properties/secure
{
  "environment": "prod",
  "key": "crm-creds",
  "properties": {
    "crm.client.id": "...",
    "crm.client.secret": "..."
  }
}
```

**Step 3: Update Applications**
```bash
# For each app, replace credentials with reference
PUT /v1/properties
{
  "environment": "prod",
  "key": "app-name",
  "properties": {
    "secure.properties": "crm-creds"
    // Remove old crm.client.id and crm.client.secret
  }
}
```

**Step 4: Delete Old Secrets**
```bash
# After all apps updated, delete duplicates
az keyvault secret delete --vault-name your-vault --name "prod--app1--crm.client.id"
az keyvault secret delete --vault-name your-vault --name "prod--app1--crm.client.secret"
# ... repeat for other apps
```

---

## Monitoring

### Key Metrics

Monitor in Application Insights:
- **Request volume**: `/v1/properties/secure` calls per minute
- **Error rate**: 4xx/5xx responses
- **Latency**: P50, P95, P99 response times
- **Cache hit rate**: Percentage of cached responses

### Alerts

Set up alerts for:
- High error rate (>1% over 5 minutes)
- Unusual access patterns (spike in secure property access)
- Failed authentication attempts

---

## FAQ

### Q: What's the difference between regular and secure properties?

**A**: Technically, they're stored the same way in Azure Key Vault. The difference is **semantic**:
- **Regular properties**: App-specific configuration (endpoints, settings, etc.)
- **Secure properties**: Shared secrets referenced by multiple apps (credentials, API keys, etc.)

### Q: Can one secure property reference another?

**A**: No, secure properties cannot be nested. Applications can only reference one level of secure properties.

### Q: What happens if I delete secure properties that apps are referencing?

**A**: The application's `secure.properties` key will still exist, but fetching that secure property will return empty. Plan carefully before deletion.

### Q: How do I know which apps are using a secure property?

**A**: Currently, you need to search application properties for `"secure.properties": "your-secure-key"`. Future enhancement: add reverse lookup API.

### Q: Can I use secure properties in local development?

**A**: Yes! Same API, just point to your local/dev environment. Use separate secure properties for each environment.

---

## Implementation Details

### Code Changes

1. **`function_app.py`**: Added 4 new endpoint functions + 1 helper function (290 lines)
2. **Unit tests**: Added 4 tests in `test_function_app.py`
3. **Integration tests**: Added 2 comprehensive tests in `test_api_integration.py`
4. **Documentation**: This file + README updates

### Files Modified

- `function_app.py` - New endpoints
- `tests/unit/test_function_app.py` - New unit tests
- `tests/integration/test_api_integration.py` - New integration tests
- `README.md` - API documentation
- `docs/8_SECURE_PROPERTIES_FEATURE.md` - This file

### Backward Compatibility

✅ **100% backward compatible**
- Existing `/v1/properties` endpoints unchanged
- No breaking changes to request/response formats
- Secure properties are opt-in (use when needed)

---

## Future Enhancements

### Potential Features

1. **Reverse Lookup API**
   - `GET /v1/properties/secure/{env}/{key}/references`
   - Returns list of applications referencing this secure property

2. **Bulk Migration Tool**
   - Automated migration from duplicated credentials to secure properties
   - Analysis tool to identify duplication

3. **Version History**
   - Track changes to secure properties
   - Rollback capability for bad credential rotations

4. **Notification System**
   - Webhook when secure properties are updated
   - Alert applications to refresh credentials

5. **Advanced Access Control**
   - Per-secure-property access control
   - Different authentication for different secure properties

---

**Status**: ✅ **PRODUCTION READY**  
**Version**: 2.1.0  
**Last Updated**: November 2025  
**Implemented by**: Staff Engineer  
**Reviewed by**: Principal Engineer

