#!/bin/bash
# Production-grade deployment script for Azure Key Vault Properties API

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if required parameters are provided
if [ $# -lt 2 ]; then
    print_error "Usage: ./deploy.sh <function-app-name> <resource-group> [key-vault-name]"
    exit 1
fi

FUNCTION_APP_NAME=$1
RESOURCE_GROUP=$2
KEY_VAULT_NAME=${3:-""}

print_info "Starting deployment for Function App: $FUNCTION_APP_NAME"
print_info "Resource Group: $RESOURCE_GROUP"

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    print_error "Azure CLI is not installed. Please install it first."
    exit 1
fi

# Check if logged in
if ! az account show &> /dev/null; then
    print_error "Not logged in to Azure. Please run 'az login' first."
    exit 1
fi

# Check if Azure Functions Core Tools is installed
if ! command -v func &> /dev/null; then
    print_error "Azure Functions Core Tools is not installed."
    print_info "Install from: https://docs.microsoft.com/azure/azure-functions/functions-run-local"
    exit 1
fi

# Verify resource group exists
print_info "Verifying resource group..."
if ! az group show --name "$RESOURCE_GROUP" &> /dev/null; then
    print_error "Resource group '$RESOURCE_GROUP' does not exist."
    exit 1
fi

# Verify function app exists
print_info "Verifying function app..."
if ! az functionapp show --name "$FUNCTION_APP_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
    print_error "Function app '$FUNCTION_APP_NAME' does not exist."
    print_info "Create it first using the Azure Portal or CLI."
    exit 1
fi

# Enable managed identity if not already enabled
print_info "Enabling managed identity..."
PRINCIPAL_ID=$(az functionapp identity assign \
    --name "$FUNCTION_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query principalId -o tsv 2>/dev/null)

if [ -n "$PRINCIPAL_ID" ]; then
    print_info "Managed Identity Principal ID: $PRINCIPAL_ID"
else
    print_warning "Could not retrieve Principal ID"
fi

# Configure Key Vault access if Key Vault name is provided
if [ -n "$KEY_VAULT_NAME" ]; then
    print_info "Configuring Key Vault access..."
    
    if az keyvault show --name "$KEY_VAULT_NAME" &> /dev/null; then
        az keyvault set-policy \
            --name "$KEY_VAULT_NAME" \
            --object-id "$PRINCIPAL_ID" \
            --secret-permissions get list set delete \
            --output none
        
        print_info "Key Vault access configured successfully"
        
        # Set Key Vault URL in app settings
        KEY_VAULT_URL="https://${KEY_VAULT_NAME}.vault.azure.net/"
        az functionapp config appsettings set \
            --name "$FUNCTION_APP_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --settings "AZURE_KEY_VAULT_URL=$KEY_VAULT_URL" \
            --output none
    else
        print_warning "Key Vault '$KEY_VAULT_NAME' not found. Skipping access configuration."
    fi
fi

# Deploy the function
print_info "Deploying function app..."
func azure functionapp publish "$FUNCTION_APP_NAME" --python

if [ $? -eq 0 ]; then
    print_info "Deployment completed successfully!"
    
    # Get function app URL
    HOSTNAME=$(az functionapp show \
        --name "$FUNCTION_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query defaultHostName -o tsv)
    
    print_info "Function App URL: https://${HOSTNAME}"
    print_info "API Endpoint: https://${HOSTNAME}/v1/properties"
    
    print_warning "Remember to configure the following app settings in Azure Portal:"
    print_warning "  - VALID_CLIENT_ID"
    print_warning "  - VALID_CLIENT_SECRET"
    print_warning "  - LOG_LEVEL (optional, defaults to INFO)"
else
    print_error "Deployment failed!"
    exit 1
fi

print_info "Deployment script completed!"

