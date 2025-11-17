#!/bin/bash

# Kubernetes Resource Export Script
# Exports various Kubernetes resources from a specified namespace

# Don't exit on errors, we'll handle them gracefully
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    print_error "kubectl is not installed. Please install kubectl first."
    exit 1
fi

# Get namespace from user input
if [ -z "$1" ]; then
    read -p "Enter the namespace to export: " NAMESPACE
else
    NAMESPACE=$1
fi

# Verify namespace exists
if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
    print_error "Namespace '$NAMESPACE' does not exist."
    exit 1
fi

# Create export directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
EXPORT_DIR="k8s_export_${NAMESPACE}_${TIMESTAMP}"
mkdir -p "$EXPORT_DIR"

print_info "Exporting resources from namespace: $NAMESPACE"
print_info "Export directory: $EXPORT_DIR"

# Function to export resources
export_resource() {
    local resource_type=$1
    local resource_name=$2
    local namespace_flag=$3
    
    local dir="$EXPORT_DIR/$resource_type"
    mkdir -p "$dir"
    
    if [ "$namespace_flag" = "cluster" ]; then
        # For cluster-scoped resources (like PV)
        local resources=$(kubectl get "$resource_type" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    else
        # For namespaced resources
        local resources=$(kubectl get "$resource_type" -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    fi
    
    if [ -z "$resources" ]; then
        print_warn "No $resource_name found"
        return 0
    fi
    
    local count=0
    for res in $resources; do
        print_info "Exporting $resource_name: $res"
        if [ "$namespace_flag" = "cluster" ]; then
            kubectl get "$resource_type" "$res" -o yaml > "$dir/${res}.yaml" 2>/dev/null
            if [ $? -eq 0 ]; then
                ((count++))
            else
                print_warn "Failed to export $res"
            fi
        else
            kubectl get "$resource_type" "$res" -n "$NAMESPACE" -o yaml > "$dir/${res}.yaml" 2>/dev/null
            if [ $? -eq 0 ]; then
                ((count++))
            else
                print_warn "Failed to export $res"
            fi
        fi
    done
    
    if [ $count -gt 0 ]; then
        print_info "Exported $count $resource_name"
    fi
    
    return 0
}

# Export StatefulSets
print_info "\n=== Exporting StatefulSets ==="
export_resource "statefulset" "StatefulSets" "namespaced"

# Export Deployments
print_info "\n=== Exporting Deployments ==="
export_resource "deployment" "Deployments" "namespaced"

# Export Services
print_info "\n=== Exporting Services ==="
export_resource "service" "Services" "namespaced"

# Export ConfigMaps
print_info "\n=== Exporting ConfigMaps ==="
export_resource "configmap" "ConfigMaps" "namespaced"

# Export Secrets
print_info "\n=== Exporting Secrets ==="
export_resource "secret" "Secrets" "namespaced"

# Export Ingresses
print_info "\n=== Exporting Ingresses ==="
export_resource "ingress" "Ingresses" "namespaced"

# Export HPA (Horizontal Pod Autoscalers)
print_info "\n=== Exporting HPAs ==="
export_resource "hpa" "HPAs" "namespaced"

# Export PVCs (PersistentVolumeClaims)
print_info "\n=== Exporting PVCs ==="
export_resource "pvc" "PVCs" "namespaced"

# Export ALL PVs (PersistentVolumes - cluster scoped)
print_info "\n=== Exporting ALL PVs ==="
mkdir -p "$EXPORT_DIR/pv"
PVS=$(kubectl get pv -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

if [ -z "$PVS" ]; then
    print_warn "No PersistentVolumes found in the cluster"
else
    pv_count=0
    for pv in $PVS; do
        print_info "Exporting PV: $pv"
        kubectl get pv "$pv" -o yaml > "$EXPORT_DIR/pv/${pv}.yaml" 2>/dev/null
        if [ $? -eq 0 ]; then
            ((pv_count++))
        else
            print_warn "Failed to export PV: $pv"
        fi
    done
    if [ $pv_count -gt 0 ]; then
        print_info "Exported $pv_count PersistentVolumes (all cluster PVs)"
    fi
fi

# Create a summary file
SUMMARY_FILE="$EXPORT_DIR/export_summary.txt"
cat > "$SUMMARY_FILE" << EOF
Kubernetes Resource Export Summary
===================================
Namespace: $NAMESPACE
Export Date: $(date)
Export Directory: $EXPORT_DIR

Resources Exported:
-------------------
EOF

for resource_dir in "$EXPORT_DIR"/*; do
    if [ -d "$resource_dir" ]; then
        resource_type=$(basename "$resource_dir")
        file_count=$(find "$resource_dir" -name "*.yaml" | wc -l)
        echo "- $resource_type: $file_count files" >> "$SUMMARY_FILE"
    fi
done

print_info "\n=== Export Complete ==="
print_info "All resources exported to: $EXPORT_DIR"
print_info "Summary saved to: $SUMMARY_FILE"

# Optional: Create a tar.gz archive
read -p "Do you want to create a tar.gz archive? (y/n): " CREATE_ARCHIVE
if [[ $CREATE_ARCHIVE =~ ^[Yy]$ ]]; then
    ARCHIVE_NAME="${EXPORT_DIR}.tar.gz"
    tar -czf "$ARCHIVE_NAME" "$EXPORT_DIR"
    print_info "Archive created: $ARCHIVE_NAME"
fi

echo ""
print_info "Done!"
