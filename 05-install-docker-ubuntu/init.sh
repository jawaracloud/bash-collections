#!/bin/bash

# Docker Installation Script for Ubuntu

# Exit immediately if a command exits with a non-zero status
set -e

# Function to log messages
log() {
    echo "[*] $1"
}

# Function to handle errors
error_exit() {
    echo "[ERROR] $1" >&2
    exit 1
}

# Check if script is run with sudo or as root
if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run with sudo or as root"
fi

# Ensure system is up to date
log "Updating package lists"
apt-get update || error_exit "Failed to update package lists"

# Install required dependencies
log "Installing required dependencies"
apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    || error_exit "Failed to install dependencies"

# Create directory for Docker GPG key
log "Preparing to add Docker repository"
mkdir -p /etc/apt/keyrings

# Download and add Docker's official GPG key
log "Adding Docker's GPG key"
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
log "Adding Docker repository to sources"
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package lists again
log "Updating package lists after adding repository"
apt-get update || error_exit "Failed to update package lists after adding Docker repository"

# Install Docker components
log "Installing Docker components"
apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin \
    || error_exit "Failed to install Docker components"

# Add current user to docker group
log "Adding current user to docker group"
usermod -aG docker $SUDO_USER || error_exit "Failed to add user to docker group"

# Verify Docker installation
log "Verifying Docker installation"
docker --version || error_exit "Docker installation failed"

log "Docker installation completed successfully!"
log "Please log out and log back in for group changes to take effect"

# Optional: Start and enable Docker service
systemctl start docker
systemctl enable docker

exit 0
