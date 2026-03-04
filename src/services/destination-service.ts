import { getDestination, HttpDestination } from '@sap-cloud-sdk/connectivity';
import xsenv from '@sap/xsenv';
import { Logger } from '../utils/logger.js';
import { Config } from '../utils/config.js';

/**
 * Decode JWT payload without verification — for diagnostic logging only.
 * Returns the parsed claims or an error indicator if decoding fails.
 */
function decodeJwtClaims(token: string): Record<string, unknown> {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return { _error: 'not a JWT (wrong segment count)' };
        const payload = Buffer.from(parts[1], 'base64url').toString('utf-8');
        return JSON.parse(payload);
    } catch {
        return { _error: 'failed to decode JWT payload' };
    }
}

export class DestinationService {
    private config: Config;
    private vcapServices!: Record<string, unknown>;

    constructor(
        private logger: Logger,
        config?: Config
    ) {
        this.config = config || new Config();
    }

    async initialize(): Promise<void> {
        try {
            // Load VCAP services
            xsenv.loadEnv();
            this.vcapServices = xsenv.getServices({
                destination: { label: 'destination' },
                connectivity: { label: 'connectivity' },
                xsuaa: { label: 'xsuaa' }
            });

            this.logger.info('Destination service initialized successfully');

        } catch (error) {
            this.logger.error('Failed to initialize destination service:', error);
            throw error;
        }
    }

    /**
     * Get destination for API discovery (uses technical user)
     */
    async getDiscoveryDestination(): Promise<HttpDestination> {
        const destinationName = this.config.get('sap.discoveryDestinationName',
            this.config.get('sap.destinationName', 'SAP_SYSTEM'));

        this.logger.debug(`Fetching discovery destination: ${destinationName}`);
        return this.getDestination(destinationName, undefined);
    }

    /**
     * Get destination for API execution (uses JWT token if provided)
     */
    async getExecutionDestination(jwtToken?: string): Promise<HttpDestination> {
        const destinationName = this.config.get('sap.executionDestinationName',
            this.config.get('sap.destinationName', 'SAP_SYSTEM'));

        this.logger.debug(`Fetching execution destination: ${destinationName}`);
        return this.getDestination(destinationName, jwtToken);
    }

    /**
     * Legacy method for backward compatibility
     */
    async getSAPDestination(): Promise<HttpDestination> {
        return this.getDiscoveryDestination();
    }

    /**
     * Internal method to get destination with optional JWT
     */
    private async getDestination(destinationName: string, jwtToken?: string): Promise<HttpDestination> {
        this.logger.debug(`Fetching destination: ${destinationName} ${jwtToken ? 'with JWT' : 'without JWT'}`);

        // ── Principal Propagation diagnostics ────────────────────────────────────
        // Decode and log JWT claims (without verification) so we can see exactly
        // which user identity is being forwarded to the Cloud Connector.
        if (jwtToken) {
            const claims = decodeJwtClaims(jwtToken);
            this.logger.info('PP-DIAG: JWT claims being forwarded for destination lookup', {
                destination: destinationName,
                iss: claims['iss'],
                // user_name is what the Cloud Connector maps to the backend user
                user_name: claims['user_name'],
                // origin indicates IdP source: 'sap.default' = XSUAA native,
                // any other value (e.g. 'sap.custom', IAS tenant ID) means federated IdP
                origin: claims['origin'],
                // zid = identity zone; must match Cloud Connector's trusted zone
                zid: claims['zid'],
                // ext_attr may carry 'enhancer' (IAS), 'serviceinstanceid', etc.
                ext_attr: claims['ext_attr'],
                // cid = client_id that issued the token
                cid: claims['cid'],
                // sub is the subject (user UUID in IAS-federated tokens)
                sub: claims['sub'],
                // exp for token expiry check
                exp: claims['exp'],
                exp_human: claims['exp']
                    ? new Date((claims['exp'] as number) * 1000).toISOString()
                    : undefined,
                grant_type: claims['grant_type'],
                // scopes present in the token
                scope: claims['scope'],
            });
        } else {
            this.logger.info('PP-DIAG: No user JWT — using technical user / client credentials for destination lookup', {
                destination: destinationName,
            });
        }
        // ─────────────────────────────────────────────────────────────────────────

        try {
            // First try environment variables (for local development)
            const envDestinations = process.env.destinations;
            if (envDestinations) {
                const destinations = JSON.parse(envDestinations);
                const envDest = destinations.find((d: Record<string, unknown>) => d.name === destinationName);
                if (envDest) {
                    this.logger.info(`Successfully retrieved destination '${destinationName}' from environment variable.`);
                    return {
                        url: envDest.url,
                        username: envDest.username,
                        password: envDest.password,
                        authentication: 'BasicAuthentication'
                    } as HttpDestination;
                }
            }
        } catch (envError) {
            this.logger.debug('Failed to load from environment destinations:', envError);
        }

        try {
            // Use SAP Cloud SDK getDestination with optional JWT
            const destination = await getDestination({
                destinationName,
                jwt: jwtToken || this.getJWT()
            });
            if (!destination) {
                throw new Error(`Destination '${destinationName}' not found in environment variables or BTP destination service`);
            }

            // ── Log the resolved destination auth configuration ─────────────────
            const dest = destination as HttpDestination & Record<string, unknown>;
            this.logger.info('PP-DIAG: Resolved destination configuration', {
                destination: destinationName,
                url: dest.url,
                // authentication type tells us what auth mechanism will be used:
                // 'PrincipalPropagation' means Cloud Connector SSO
                // 'OAuth2UserTokenExchange' means BTP token exchange
                // 'OAuth2SAMLBearerAssertion' means SAML bearer
                authentication: dest.authentication,
                proxyType: dest.proxyType,
                // forwardAuthToken would indicate the raw token is forwarded
                forwardAuthToken: dest.forwardAuthToken,
            });
            // ─────────────────────────────────────────────────────────────────────

            this.logger.info(`Successfully retrieved destination: ${destinationName}`);
            return destination as HttpDestination;
        } catch (error) {
            this.logger.error('PP-DIAG: Failed to get SAP destination — check Cloud Connector trust and destination config:', error);
            throw error;
        }
    }

    private getJWT(): string | undefined {
        // In a real application, this would extract JWT from the current request
        // For technical user scenario, this might not be needed
        return process.env.USER_JWT || undefined;
    }

    getDestinationCredentials() {
        return (this.vcapServices?.destination as { credentials?: unknown })?.credentials;
    }

    getConnectivityCredentials() {
        return (this.vcapServices?.connectivity as { credentials?: unknown })?.credentials;
    }

    getXSUAACredentials() {
        return (this.vcapServices?.xsuaa as { credentials?: unknown })?.credentials;
    }
}