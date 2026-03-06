import axios from 'axios';
import { Logger } from '../utils/logger.js';

export interface EntityPermissions {
    read: boolean;
    'read-single': boolean;
    create: boolean;
    update: boolean;
    delete: boolean;
}

export interface PermissionMap {
    [serviceId: string]: {
        [entityName: string]: EntityPermissions;
    };
}

/** XSUAA credentials used to obtain a client_credentials token. */
export interface XsuaaCredentials {
    /** XSUAA tenant base URL, e.g. https://mysubaccount.authentication.ap10.hana.ondemand.com */
    url: string;
    clientid: string;
    clientsecret: string;
}

interface CachedPermissions {
    permissions: PermissionMap;
    fetchedAt: number;
}

interface CachedClientToken {
    token: string;
    /** Unix timestamp (ms) after which the token must be refreshed. */
    expiresAt: number;
}

export type EnforcementMode = 'strict' | 'permissive';

/**
 * PermissionCheckService
 *
 * Checks whether the authenticated user has the required CRUD permission
 * for a given SAP OData service + entity combination by querying the
 * MCP Config App's `effectivePermissions` OData function.
 *
 * Server-to-server authentication uses OAuth2 client_credentials obtained
 * from the shared XSUAA instance (`sap-mcp-xsuaa`) that is bound to both
 * the MCP server and the Config App.
 *
 * Results are cached per-user for `cacheTtlMs` milliseconds (default 5 min)
 * to avoid a remote call on every MCP tool invocation.
 *
 * Enforcement modes:
 *   strict     - Deny the operation if the permission service is unavailable or
 *                no permission record exists. (default, recommended for production)
 *   permissive - Allow the operation when the service is unavailable, but still
 *                deny when a record explicitly denies access. Useful during roll-out.
 */
export class PermissionCheckService {
    private readonly cache = new Map<string, CachedPermissions>();
    private readonly configAppUrl: string;
    private readonly cacheTtlMs: number;
    private readonly enforcementMode: EnforcementMode;
    private readonly xsuaaCredentials?: XsuaaCredentials;
    private clientCredentialsToken?: CachedClientToken;

    constructor(
        private readonly logger: Logger,
        configAppUrl: string,
        cacheTtlMs = 5 * 60 * 1000,
        enforcementMode: EnforcementMode = 'strict',
        xsuaaCredentials?: XsuaaCredentials
    ) {
        // Strip trailing slash for consistent URL building
        this.configAppUrl = configAppUrl.replace(/\/$/, '');
        this.cacheTtlMs = cacheTtlMs;
        this.enforcementMode = enforcementMode;
        this.xsuaaCredentials = xsuaaCredentials;

        if (this.configAppUrl && xsuaaCredentials) {
            logger.info('[PermissionCheck] Client credentials auth configured for Config App calls');
        } else if (this.configAppUrl && !xsuaaCredentials) {
            logger.warn(
                '[PermissionCheck] No XSUAA credentials found — Config App calls will be unauthenticated. ' +
                'Ensure sap-mcp-xsuaa is bound to this application.'
            );
        }
    }

    /**
     * Returns true if a Config App URL has been configured.
     * When false, all permission checks are skipped (allow-all).
     */
    isConfigured(): boolean {
        return !!this.configAppUrl;
    }

    /**
     * Check whether `userId` may perform `operation` on the given entity.
     *
     * @param userId     - The authenticated user's login name / email
     * @param serviceId  - SAP OData service ID (e.g. "API_BUSINESS_PARTNER")
     * @param entityName - OData EntitySet name   (e.g. "A_BusinessPartner")
     * @param operation  - One of: read | read-single | create | update | delete
     */
    async checkPermission(
        userId: string,
        serviceId: string,
        entityName: string,
        operation: string
    ): Promise<{ allowed: boolean; reason?: string }> {

        if (!this.isConfigured()) {
            this.logger.warn(
                `[PermissionCheck] MCP_CONFIG_APP_URL not set — skipping permission check`,
                { userId, serviceId, entityName, operation }
            );
            return { allowed: true };
        }

        let permissions: PermissionMap;
        try {
            permissions = await this.fetchPermissionsForUser(userId);
        } catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            this.logger.error(
                `[PermissionCheck] Failed to fetch permissions for user '${userId}': ${msg}`
            );

            if (this.enforcementMode === 'permissive') {
                this.logger.warn(
                    `[PermissionCheck] Permissive mode — allowing operation despite fetch failure`,
                    { userId, serviceId, entityName, operation }
                );
                return { allowed: true };
            }

            return {
                allowed: false,
                reason: `[ACCESS DENIED] Unable to verify permissions for user '${userId}'. ` +
                    `The permission service is temporarily unavailable. ` +
                    `Please try again shortly or contact your administrator.`
            };
        }

        const servicePerms = permissions[serviceId];
        if (!servicePerms) {
            return {
                allowed: false,
                reason: `[ACCESS DENIED] User '${userId}' has no permissions configured for ` +
                    `service '${serviceId}'. ` +
                    `Contact your administrator to request access.`
            };
        }

        const entityPerms = servicePerms[entityName];
        if (!entityPerms) {
            return {
                allowed: false,
                reason: `[ACCESS DENIED] User '${userId}' has no permissions configured for ` +
                    `entity '${entityName}' in service '${serviceId}'. ` +
                    `Contact your administrator to request access.`
            };
        }

        const allowed = entityPerms[operation as keyof EntityPermissions] === true;

        if (!allowed) {
            const opLabel = this.operationLabel(operation);
            return {
                allowed: false,
                reason: `[ACCESS DENIED] User '${userId}' does not have '${opLabel}' ` +
                    `permission for entity '${entityName}' in service '${serviceId}'. ` +
                    `Contact your administrator to request the '${operation}' permission.`
            };
        }

        this.logger.debug(
            `[PermissionCheck] Access granted`,
            { userId, serviceId, entityName, operation }
        );
        return { allowed: true };
    }

    /**
     * Invalidate the cached permissions for a user.
     * Call this if you know the user's permissions have changed.
     */
    invalidateCache(userId: string): void {
        this.cache.delete(userId);
        this.logger.debug(`[PermissionCheck] Cache invalidated for user '${userId}'`);
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /**
     * Obtain a client_credentials access token from XSUAA and cache it until
     * it's within 60 seconds of expiry.
     */
    private async getClientCredentialsToken(): Promise<string> {
        if (
            this.clientCredentialsToken &&
            Date.now() < this.clientCredentialsToken.expiresAt
        ) {
            return this.clientCredentialsToken.token;
        }

        const { url, clientid, clientsecret } = this.xsuaaCredentials!;
        const tokenUrl = `${url.replace(/\/$/, '')}/oauth/token`;

        this.logger.debug('[PermissionCheck] Fetching client credentials token', { tokenUrl });

        const response = await axios.post<{ access_token: string; expires_in: number }>(
            tokenUrl,
            'grant_type=client_credentials&response_type=token',
            {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                auth: { username: clientid, password: clientsecret },
                timeout: 10_000
            }
        );

        const { access_token, expires_in } = response.data;
        // Cache with a 60-second buffer before true expiry
        this.clientCredentialsToken = {
            token: access_token,
            expiresAt: Date.now() + Math.max(0, (expires_in - 60)) * 1000
        };

        this.logger.debug('[PermissionCheck] Client credentials token cached', {
            expiresInSeconds: expires_in
        });

        return access_token;
    }

    private async fetchPermissionsForUser(userId: string): Promise<PermissionMap> {
        const cached = this.cache.get(userId);
        if (cached && (Date.now() - cached.fetchedAt) < this.cacheTtlMs) {
            this.logger.debug(`[PermissionCheck] Using cached permissions for '${userId}'`);
            return cached.permissions;
        }

        // CAP OData v4 function call: GET /odata/v4/access/effectivePermissions(userId='...')
        const url = `${this.configAppUrl}/odata/v4/access/effectivePermissions(userId='${encodeURIComponent(userId)}')`;
        this.logger.debug(`[PermissionCheck] Fetching permissions from Config App`, { url });

        // Build auth header — use client credentials if XSUAA is configured
        const headers: Record<string, string> = { Accept: 'application/json' };
        if (this.xsuaaCredentials) {
            const token = await this.getClientCredentialsToken();
            headers['Authorization'] = `Bearer ${token}`;
        }

        const response = await axios.get<{ value: string }>(url, {
            headers,
            timeout: 10_000
        });

        // CAP returns LargeString as a JSON-encoded string in the `value` field
        const rawValue = response.data?.value;
        if (rawValue === undefined || rawValue === null) {
            throw new Error(
                `Unexpected response from permission service — 'value' field missing`
            );
        }

        const parsed: { userId: string; permissions: PermissionMap } =
            typeof rawValue === 'string' ? JSON.parse(rawValue) : rawValue;

        const permissions: PermissionMap = parsed.permissions ?? {};

        this.cache.set(userId, { permissions, fetchedAt: Date.now() });
        this.logger.debug(
            `[PermissionCheck] Permissions cached for '${userId}'`,
            { serviceCount: Object.keys(permissions).length }
        );

        return permissions;
    }

    private operationLabel(operation: string): string {
        const labels: Record<string, string> = {
            'read':        'Read (collection)',
            'read-single': 'Read (single record)',
            'create':      'Create',
            'update':      'Update/PATCH',
            'delete':      'Delete'
        };
        return labels[operation] ?? operation;
    }

    /**
     * Decode a JWT payload to extract the user identifier.
     *
     * Priority order of claims:
     *   1. user_name          — SAP XSUAA native user login
     *   2. preferred_username — OIDC standard claim (IAS federation)
     *   3. email              — fallback for IAS-issued tokens
     *   4. sub                — last-resort UUID subject
     *
     * This does NOT verify the token signature — authentication is already
     * performed by the auth middleware before any tool handler is called.
     */
    static extractUserIdFromToken(token: string): string | undefined {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return undefined;
            const payload = JSON.parse(
                Buffer.from(parts[1], 'base64url').toString('utf-8')
            ) as Record<string, unknown>;
            return (
                (payload.user_name as string | undefined) ||
                (payload.preferred_username as string | undefined) ||
                (payload.email as string | undefined) ||
                (payload.sub as string | undefined)
            );
        } catch {
            return undefined;
        }
    }
}
