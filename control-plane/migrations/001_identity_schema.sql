-- ============================================================================
-- BADGER PHASE 3: IDENTITY INTELLIGENCE & MACHINE IDENTITY GRAPH
-- Migration: 001_identity_schema.sql
-- Database Target: PostgreSQL 14+
-- Description: Relational schema for canonical identity, graph topology,
--              keyed credential fingerprints, connectors telemetry, and drift findings.
-- ============================================================================

-- Ensure pgcrypto extension is available for UUID generation if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ----------------------------------------------------------------------------
-- 1. Tenants Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_tenants_created_at ON tenants (created_at);

-- ----------------------------------------------------------------------------
-- 2. Principals Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS principals (
    id VARCHAR(128) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    principal_type VARCHAR(32) NOT NULL CHECK (principal_type IN ('Agent', 'Human', 'ServiceAccount', 'Workload', 'Infrastructure')),
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_principals_tenant_id ON principals (tenant_id);
CREATE INDEX IF NOT EXISTS idx_principals_type ON principals (principal_type);

-- ----------------------------------------------------------------------------
-- 3. Workloads Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workloads (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_id VARCHAR(128) NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    state VARCHAR(32) NOT NULL CHECK (state IN ('Registered', 'Staging', 'Running', 'Active', 'Suspended', 'Contained', 'Terminated', 'Failed', 'Unknown')),
    spiffe_id VARCHAR(512) NOT NULL,
    cgroup_path VARCHAR(512),
    pid INTEGER,
    policy_id VARCHAR(128) NOT NULL,
    policy_version INTEGER NOT NULL DEFAULT 1,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sensor_status VARCHAR(32) NOT NULL DEFAULT 'Unknown' CHECK (sensor_status IN ('Protected', 'Degraded', 'Unprotected', 'Unknown'))
);

CREATE INDEX IF NOT EXISTS idx_workloads_tenant_id ON workloads (tenant_id);
CREATE INDEX IF NOT EXISTS idx_workloads_principal_id ON workloads (principal_id);
CREATE INDEX IF NOT EXISTS idx_workloads_spiffe_id ON workloads (spiffe_id);
CREATE INDEX IF NOT EXISTS idx_workloads_state ON workloads (state);

-- ----------------------------------------------------------------------------
-- 4. Credentials Table (Keyed HMAC fingerprints only, strictly no raw secrets)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS credentials (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    credential_type VARCHAR(64) NOT NULL CHECK (credential_type IN ('ApiKey', 'OAuthToken', 'SpiffeX509Svid', 'AwsStsToken', 'GcpServiceAccountToken', 'K8sServiceAccountToken', 'TlsCertificate')),
    issuer VARCHAR(255) NOT NULL,
    audience VARCHAR(255) NOT NULL,
    scope JSONB NOT NULL DEFAULT '[]'::jsonb,
    fingerprint_hmac_sha256 VARCHAR(64) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    use_count BIGINT NOT NULL DEFAULT 0,
    associated_principals JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_credentials_tenant_id ON credentials (tenant_id);
CREATE INDEX IF NOT EXISTS idx_credentials_fingerprint ON credentials (tenant_id, fingerprint_hmac_sha256);
CREATE INDEX IF NOT EXISTS idx_credentials_expires_at ON credentials (expires_at);
CREATE INDEX IF NOT EXISTS idx_credentials_revoked ON credentials (is_revoked);

-- ----------------------------------------------------------------------------
-- 5. Target Resources Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS resources (
    id VARCHAR(128) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    resource_type VARCHAR(64) NOT NULL CHECK (resource_type IN ('ApiEndpoint', 'Database', 'StorageBucket', 'HostFilesystem', 'NetworkDestination', 'InternalService')),
    identifier VARCHAR(512) NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_resources_tenant_id ON resources (tenant_id);
CREATE INDEX IF NOT EXISTS idx_resources_type ON resources (resource_type);
CREATE INDEX IF NOT EXISTS idx_resources_identifier ON resources (identifier);

-- ----------------------------------------------------------------------------
-- 6. Identity Graph Relationships Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS relationships (
    id VARCHAR(128) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_id VARCHAR(128) NOT NULL,
    target_id VARCHAR(128) NOT NULL,
    relationship_type VARCHAR(64) NOT NULL CHECK (relationship_type IN (
        'OWNS', 'RUNS_AS', 'USES_CREDENTIAL', 'CAN_ACCESS',
        'DELEGATES_TO', 'CONNECTS_TO', 'EXECUTES',
        'MANAGED_BY', 'DISCOVERED_FROM', 'AUTHENTICATED_BY'
    )),
    kind VARCHAR(32) NOT NULL CHECK (kind IN ('Direct', 'Inferred')),
    confidence REAL NOT NULL DEFAULT 1.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    source_attribution VARCHAR(128) NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_to TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_relationships_tenant ON relationships (tenant_id);
CREATE INDEX IF NOT EXISTS idx_relationships_source ON relationships (tenant_id, source_id);
CREATE INDEX IF NOT EXISTS idx_relationships_target ON relationships (tenant_id, target_id);
CREATE INDEX IF NOT EXISTS idx_relationships_type ON relationships (relationship_type);
CREATE INDEX IF NOT EXISTS idx_relationships_edge ON relationships (source_id, target_id, relationship_type);

-- ----------------------------------------------------------------------------
-- 7. Identity Observations Table (Discovery Connectors Telemetry)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_observations (
    id VARCHAR(128) PRIMARY KEY,
    connector_name VARCHAR(128) NOT NULL,
    source VARCHAR(64) NOT NULL CHECK (source IN ('LinuxProcFs', 'BadgerSandbox', 'DockerDaemon', 'KubernetesApi', 'StaticConfig', 'SpiffeAuthority')),
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    entity_id VARCHAR(128) NOT NULL,
    entity_type VARCHAR(64) NOT NULL,
    raw_attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    confidence REAL NOT NULL DEFAULT 1.0
);

CREATE INDEX IF NOT EXISTS idx_observations_tenant ON identity_observations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_observations_entity ON identity_observations (tenant_id, entity_id);
CREATE INDEX IF NOT EXISTS idx_observations_connector ON identity_observations (connector_name);
CREATE INDEX IF NOT EXISTS idx_observations_timestamp ON identity_observations (timestamp DESC);

-- ----------------------------------------------------------------------------
-- 8. Identity Findings Table (Drift and Anomaly Findings)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_findings (
    id VARCHAR(128) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_type VARCHAR(64) NOT NULL CHECK (finding_type IN (
        'UnownedWorkload', 'CredentialSharing', 'ExpiredCredentialInUse',
        'OrphanedServiceAccount', 'UnexpectedDelegation', 'PrivilegeDrift',
        'DuplicateIdentity', 'CrossTenantAccessAttempt'
    )),
    severity VARCHAR(32) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    entity_id VARCHAR(128) NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    remediation TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(32) NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Remediated', 'Suppressed'))
);

CREATE INDEX IF NOT EXISTS idx_findings_tenant ON identity_findings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON identity_findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON identity_findings (status);
CREATE INDEX IF NOT EXISTS idx_findings_detected_at ON identity_findings (detected_at DESC);
