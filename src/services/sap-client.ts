import { executeHttpRequest } from '@sap-cloud-sdk/http-client';
import { HttpDestination } from '@sap-cloud-sdk/connectivity';
import { DestinationService } from './destination-service.js';
import { Logger } from '../utils/logger.js';
import { Config } from '../utils/config.js';


export class SAPClient {
    private discoveryDestination: HttpDestination | null = null;
    private config: Config;
    private currentUserToken?: string;
    /** CSRF token + session cookies cache keyed by service base path (e.g. /sap/opu/odata/sap/SERVICE_NAME/) */
    private csrfTokenCache = new Map<string, { token: string; cookies?: string }>();

    constructor(
        private destinationService: DestinationService,
        private logger: Logger
    ) {
        this.config = new Config();
    }

    /**
     * Set the current user's JWT token for subsequent operations
     */
    setUserToken(token?: string) {
        this.currentUserToken = token;
        this.logger.debug(`User token ${token ? 'set' : 'cleared'} for SAP client`);
    }

    /**
     * Get destination for discovery operations (technical user)
     */
    async getDiscoveryDestination(): Promise<HttpDestination> {
        if (!this.discoveryDestination) {
            this.discoveryDestination = await this.destinationService.getDiscoveryDestination();
        }
        return this.discoveryDestination;
    }

    /**
     * Get destination for execution operations (with JWT if available)
     */
    async getExecutionDestination(): Promise<HttpDestination> {
        return await this.destinationService.getExecutionDestination(this.currentUserToken);
    }

    /**
     * Legacy method - defaults to discovery destination
     */
    async getDestination(): Promise<HttpDestination> {
        return this.getDiscoveryDestination();
    }

    /**
     * Fetch a CSRF token from a SAP service and cache it alongside any session cookies.
     * Fetches via GET {servicePath}$metadata with X-CSRF-Token: Fetch header.
     *
     * SAP CSRF tokens are session-bound: the token returned is only valid for the session
     * established during this request (identified by Set-Cookie headers). Both the token
     * and the session cookies must be forwarded on subsequent write requests.
     */
    async fetchCsrfToken(servicePath: string): Promise<{ token: string; cookies?: string }> {
        const destination = await this.getExecutionDestination();

        try {
            const response = await executeHttpRequest(destination as HttpDestination, {
                method: 'GET',
                url: `${servicePath}$metadata`,
                headers: {
                    'X-CSRF-Token': 'Fetch',
                    'Accept': 'application/xml'
                }
            });

            // HTTP headers are normalised to lowercase in Node.js
            const token = (response.headers as Record<string, string | string[]>)?.['x-csrf-token'] as string
                       || (response.headers as Record<string, string | string[]>)?.['X-CSRF-Token'] as string;

            if (!token) {
                throw new Error('No X-CSRF-Token header returned from SAP system');
            }

            // Capture session cookies — SAP CSRF tokens are session-bound and will be
            // rejected with 403 if the matching session cookie is not forwarded.
            const setCookie = (response.headers as Record<string, string | string[]>)?.['set-cookie'];
            let cookies: string | undefined;
            if (setCookie) {
                // Each Set-Cookie entry may contain attributes (e.g. "name=val; Path=/; HttpOnly").
                // Extract only the name=value pair from each cookie before joining.
                const entries = Array.isArray(setCookie) ? setCookie : [setCookie];
                cookies = entries
                    .map(c => c.split(';')[0].trim())
                    .filter(Boolean)
                    .join('; ');
            }

            const entry = { token, cookies };
            this.csrfTokenCache.set(servicePath, entry);
            this.logger.debug(`CSRF token fetched and cached for service: ${servicePath}${cookies ? ' (with session cookies)' : ''}`);
            return entry;

        } catch (error) {
            this.logger.warn(`Failed to fetch CSRF token for ${servicePath}:`, error);
            throw error;
        }
    }

    /**
     * Get a cached CSRF token+cookies entry or fetch a new one.
     */
    async getCsrfToken(servicePath: string): Promise<{ token: string; cookies?: string }> {
        const cached = this.csrfTokenCache.get(servicePath);
        if (cached) {
            return cached;
        }
        return this.fetchCsrfToken(servicePath);
    }

    /**
     * Invalidate a cached CSRF token (e.g. after a 403 response).
     */
    invalidateCsrfToken(servicePath: string): void {
        this.csrfTokenCache.delete(servicePath);
    }

    /**
     * Determine whether an error is a CSRF-token-related 403.
     */
    private isCsrfError(error: unknown): boolean {
        if (typeof error === 'object' && error !== null) {
            const err = error as {
                rootCause?: { response?: { status?: number } };
                response?: { status?: number };
                status?: number;
            };
            const status = err.rootCause?.response?.status ?? err.response?.status ?? err.status;
            return status === 403;
        }
        return false;
    }

    async executeRequest(options: {
        url: string;
        method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
        data?: unknown;
        headers?: Record<string, string>;
        isDiscovery?: boolean;
        /** Service base path used to scope CSRF token caching (e.g. /sap/opu/odata/sap/SERVICE/) */
        servicePath?: string;
    }) {
        const destination = options.isDiscovery
            ? await this.getDiscoveryDestination()
            : await this.getExecutionDestination();

        const extraHeaders: Record<string, string> = {};

        // Auto-fetch CSRF token (+ session cookies) for write operations
        const needsCsrf = ['POST', 'PATCH', 'PUT', 'DELETE'].includes(options.method);
        if (needsCsrf && !options.isDiscovery && options.servicePath) {
            try {
                const { token, cookies } = await this.getCsrfToken(options.servicePath);
                extraHeaders['X-CSRF-Token'] = token;
                // SAP CSRF tokens are session-bound: forward the session cookie so SAP
                // can validate the token against the correct session.
                if (cookies) {
                    extraHeaders['Cookie'] = cookies;
                }
            } catch (error) {
                this.logger.warn('Could not fetch CSRF token, proceeding without it:', error);
            }
        }

        const requestOptions = {
            method: options.method,
            url: options.url,
            data: options.data,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                ...extraHeaders,
                ...options.headers
            }
        };

        try {
            // ── PP-DIAG: log destination auth type being used for this request ──
            const destWithMeta = destination as HttpDestination & Record<string, unknown>;
            this.logger.info('PP-DIAG: About to execute HTTP request', {
                method: options.method,
                url: options.url,
                isDiscovery: options.isDiscovery ?? false,
                destinationAuth: destWithMeta.authentication,
                destinationProxyType: destWithMeta.proxyType,
                hasUserToken: !!this.currentUserToken,
                hasCsrfToken: !!extraHeaders['X-CSRF-Token'],
            });
            // ─────────────────────────────────────────────────────────────────────

            if (!destination.url) {
                throw new Error('Destination URL is not configured');
            }

            const response = await executeHttpRequest(destination as HttpDestination, requestOptions);

            this.logger.debug(`Request completed successfully`);
            return response;

        } catch (error) {
            // On 403, invalidate cached CSRF token and retry once
            if (options.servicePath && this.isCsrfError(error)) {
                this.logger.info('CSRF token expired or invalid, refreshing and retrying...');
                this.invalidateCsrfToken(options.servicePath);

                try {
                    const { token: newToken, cookies: newCookies } = await this.fetchCsrfToken(options.servicePath);
                    const retryHeaders: Record<string, string> = {
                        ...requestOptions.headers as Record<string, string>,
                        'X-CSRF-Token': newToken
                    };
                    if (newCookies) {
                        retryHeaders['Cookie'] = newCookies;
                    }
                    const retryOptions = {
                        ...requestOptions,
                        headers: retryHeaders
                    };
                    const retryResponse = await executeHttpRequest(destination as HttpDestination, retryOptions);
                    this.logger.debug('Retry after CSRF refresh succeeded');
                    return retryResponse;
                } catch (retryError) {
                    this.logger.error('Retry after CSRF refresh also failed:', retryError);
                    this.logResponseBody(retryError);
                    throw this.handleError(retryError);
                }
            }

            this.logger.error(`Request failed:`, error);
            this.logResponseBody(error);
            throw this.handleError(error);
        }
    }

    async readEntitySet(servicePath: string, entitySet: string, queryOptions?: {
        $filter?: string;
        $select?: string;
        $expand?: string;
        $orderby?: string;
        $top?: number;
        $skip?: number;
        [key: string]: unknown;
    }, isDiscovery = false) {
        let url = `${servicePath}${entitySet}`;

        if (queryOptions) {
            const params = new URLSearchParams();
            Object.entries(queryOptions).forEach(([key, value]) => {
                if (value !== undefined && value !== null) {
                    params.set(key, String(value));
                }
            });

            if (params.toString()) {
                url += `?${params.toString()}`;
            }
        }

        return this.executeRequest({
            method: 'GET',
            url,
            isDiscovery,
            servicePath: isDiscovery ? undefined : servicePath
        });
    }

    /**
     * Read a single entity by its pre-formatted OData key predicate.
     * key should NOT include outer parentheses — e.g. "K1='v1',K2=false" or "'stringValue'" or "42"
     */
    async readEntity(servicePath: string, entitySet: string, key: string, isDiscovery = false) {
        const url = `${servicePath}${entitySet}(${key})`;

        return this.executeRequest({
            method: 'GET',
            url,
            isDiscovery,
            servicePath: isDiscovery ? undefined : servicePath
        });
    }

    async createEntity(servicePath: string, entitySet: string, data: unknown) {
        const url = `${servicePath}${entitySet}`;

        return this.executeRequest({
            method: 'POST',
            url,
            data,
            servicePath
        });
    }

    /**
     * PATCH an entity identified by a pre-formatted OData key predicate.
     * key should NOT include outer parentheses.
     */
    async updateEntity(servicePath: string, entitySet: string, key: string, data: unknown) {
        const url = `${servicePath}${entitySet}(${key})`;

        return this.executeRequest({
            method: 'PATCH',
            url,
            data,
            servicePath
        });
    }

    /**
     * DELETE an entity identified by a pre-formatted OData key predicate.
     * key should NOT include outer parentheses.
     */
    async deleteEntity(servicePath: string, entitySet: string, key: string) {
        const url = `${servicePath}${entitySet}(${key})`;

        return this.executeRequest({
            method: 'DELETE',
            url,
            servicePath
        });
    }

    /**
     * Execute an OData Function Import or Action.
     *
     * @param servicePath  - Service base URL (e.g. /sap/opu/odata/sap/SERVICE_NAME/)
     * @param functionPath - Path relative to service, already including entity path and
     *                       function name (e.g. "EntitySet(K='v')/namespace.EditAction"
     *                       or just "AssignSourceOfSupply")
     * @param body         - Request body for POST operations
     * @param method       - HTTP method (default POST)
     * @param queryParams  - Query parameters appended for GET function imports
     */
    async executeFunctionImport(
        servicePath: string,
        functionPath: string,
        body?: unknown,
        method: 'GET' | 'POST' = 'POST',
        queryParams?: Record<string, unknown>
    ) {
        let url = `${servicePath}${functionPath}`;

        if (method === 'GET' && queryParams && Object.keys(queryParams).length > 0) {
            const params = new URLSearchParams();
            Object.entries(queryParams).forEach(([key, value]) => {
                if (value !== undefined && value !== null) {
                    params.set(key, String(value));
                }
            });
            if (params.toString()) {
                url += `?${params.toString()}`;
            }
        }

        return this.executeRequest({
            method,
            url,
            data: method === 'POST' ? (body ?? {}) : undefined,
            servicePath
        });
    }

    /**
     * PATCH an entity using a fully pre-constructed entity path (including key predicate).
     * Used by the patch-sap-entity tool which builds its own key from caller-supplied keyProperties.
     *
     * @param servicePath - Service base URL
     * @param entityPath  - Entity path with key predicate, e.g. "EntitySet(K1='v1',IsActiveEntity=false)"
     * @param data        - Fields to patch
     */
    async patchEntityByPath(servicePath: string, entityPath: string, data: unknown) {
        const url = `${servicePath}${entityPath}`;

        return this.executeRequest({
            method: 'PATCH',
            url,
            data,
            servicePath
        });
    }

    /**
     * Fetch the raw $metadata XML for a service (uses discovery destination).
     *
     * @param metadataUrl - Path to $metadata endpoint (e.g. /sap/opu/odata/sap/SERVICE/$metadata)
     */
    async fetchRawMetadata(metadataUrl: string): Promise<string> {
        const destination = await this.getDiscoveryDestination();

        const response = await executeHttpRequest(destination as HttpDestination, {
            method: 'GET',
            url: metadataUrl,
            headers: {
                'Accept': 'application/xml'
            }
        });

        return response.data as string;
    }

    private logResponseBody(error: unknown): void {
        if (typeof error !== 'object' || error === null) return;

        const err = error as {
            rootCause?: { response?: { status?: number; data?: unknown; headers?: Record<string, unknown> } };
            response?: { status?: number; data?: unknown; headers?: Record<string, unknown> };
        };

        const response = err.rootCause?.response ?? err.response;
        if (!response) return;

        // For 401 errors include response headers — Cloud Connector PP failures
        // often include a WWW-Authenticate header with more detail.
        const extraHeadersForLog: Record<string, unknown> = {};
        if (response.status === 401 && response.headers) {
            for (const h of ['www-authenticate', 'x-sap-login-page', 'x-error-message', 'x-error-description']) {
                if (response.headers[h]) {
                    extraHeadersForLog[h] = response.headers[h];
                }
            }
        }

        this.logger.error('Failed response details:', {
            status: response.status,
            body: response.data,
            ...(Object.keys(extraHeadersForLog).length > 0 ? { response_headers: extraHeadersForLog } : {}),
        });
    }

    private handleError(error: unknown): Error {
        if (typeof error === 'object' && error !== null) {
            type SapErrorData = {
                error?: {
                    message?: { value?: string } | string;
                    code?: string;
                    innererror?: {
                        errordetails?: Array<{
                            code?: string;
                            message?: { value?: string } | string;
                            target?: string;
                            severity?: string;
                        }>;
                    };
                };
            };
            const err = error as {
                rootCause?: { response?: { status?: number; data?: SapErrorData; statusText?: string } };
                response?: { status?: number; data?: SapErrorData; statusText?: string };
            };

            // Mirror logResponseBody: check rootCause first, fall back to response
            const response = err.rootCause?.response ?? err.response;

            if (response) {
                // Extract SAP OData error message (v2 uses message.value, v4 uses message directly)
                const sapMessage = typeof response.data?.error?.message === 'object'
                    ? response.data.error.message.value
                    : response.data?.error?.message;

                const errorCode = response.data?.error?.code;
                const errorDetails = response.data?.error?.innererror?.errordetails;

                let errorText = sapMessage || response.statusText || `HTTP ${response.status}`;

                if (errorCode) {
                    errorText += `\nSAP Error Code: ${errorCode}`;
                }

                if (Array.isArray(errorDetails) && errorDetails.length > 0) {
                    errorText += '\nField-level errors:';
                    for (const detail of errorDetails) {
                        const detailMsg = typeof detail.message === 'object'
                            ? detail.message?.value
                            : detail.message;
                        const target = detail.target ? ` [field: ${detail.target}]` : '';
                        const severity = detail.severity ? ` (${detail.severity})` : '';
                        if (detailMsg) errorText += `\n  - ${detailMsg}${target}${severity}`;
                    }
                }

                return new Error(`SAP API Error ${response.status}: ${errorText}`);
            }
        }
        return error instanceof Error ? error : new Error(String(error));
    }
}
