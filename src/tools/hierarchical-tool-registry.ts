import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SAPClient } from "../services/sap-client.js";
import { Logger } from "../utils/logger.js";
import { ODataService, EntityType } from "../types/sap-types.js";
import { PermissionCheckService } from "../services/permission-check-service.js";
import { z } from "zod";

/**
 * Hierarchical Tool Registry - Solves the "tool explosion" problem with 3-level architecture
 *
 * Instead of registering hundreds of CRUD tools upfront (5 ops × 40+ entities × services),
 * this registry uses a 3-level progressive discovery approach optimized for LLM token efficiency:
 *
 * Level 1: discover-sap-data - Lightweight search returning minimal service/entity list
 *          Returns: serviceId, serviceName, entityName only (for LLM decision making)
 *          Fallback: If no matches, returns ALL services with entities (minimal fields)
 *
 * Level 2: get-entity-metadata - Full schema details for selected service/entity
 *          Returns: Complete entity schema with properties, types, keys, capabilities
 *          Purpose: Provides LLM with all details needed to construct proper operation
 *
 * Level 3: execute-sap-operation - Execute CRUD operation with authenticated user context
 *          Uses: Metadata from Level 2 to perform actual data operations
 *
 * This reduces AI assistant context from 200+ tools to 3, solving token overflow
 * and dramatically improving tool selection for AI assistants like Claude and Microsoft Copilot.
 */
export class HierarchicalSAPToolRegistry {
    private serviceCategories = new Map<string, string[]>();
    private userToken?: string;
    /** Resolved user login name extracted from the JWT, used for permission checks. */
    private userId?: string;

    constructor(
        private mcpServer: McpServer,
        private sapClient: SAPClient,
        private logger: Logger,
        private discoveredServices: ODataService[],
        private permissionCheckService?: PermissionCheckService
    ) {
        this.categorizeServices();
    }

    /**
     * Set the user's JWT token for authenticated operations.
     * Also decodes the token to extract the userId for permission checks.
     */
    setUserToken(token?: string) {
        this.userToken = token;
        this.sapClient.setUserToken(token);

        if (token) {
            this.userId = PermissionCheckService.extractUserIdFromToken(token);
            this.logger.debug(`User token set for tool registry (userId: ${this.userId ?? 'unknown'})`);
        } else {
            this.userId = undefined;
            this.logger.debug('User token cleared for tool registry');
        }
    }

    /**
     * Enforce a permission check before executing a CRUD operation.
     * Returns an error tool response if access is denied, or undefined if access is granted.
     */
    private async enforcePermission(
        serviceId: string,
        entityName: string,
        operation: string
    ): Promise<{ content: Array<{ type: 'text'; text: string }>; isError: true } | undefined> {
        if (!this.permissionCheckService?.isConfigured()) {
            return undefined; // No permission service configured — allow
        }

        if (!this.userId) {
            const msg =
                `[ACCESS DENIED] This operation requires authentication.\n\n` +
                `No authenticated user identity could be resolved from the current session token.\n` +
                `Please authenticate via OAuth before performing data operations.`;
            this.logger.warn(`[PermissionCheck] Cannot perform check — no userId in token`, { serviceId, entityName, operation });
            return { content: [{ type: 'text' as const, text: msg }], isError: true };
        }

        const result = await this.permissionCheckService.checkPermission(
            this.userId, serviceId, entityName, operation
        );

        if (!result.allowed) {
            this.logger.warn(`[PermissionCheck] Access denied`, { userId: this.userId, serviceId, entityName, operation });
            return { content: [{ type: 'text' as const, text: result.reason! }], isError: true };
        }

        return undefined; // Access granted
    }

    /**
     * Register the 3-level progressive discovery tools instead of 200+ individual CRUD tools
     */
    public async registerDiscoveryTools(): Promise<void> {
        this.logger.info(`🔧 Registering 3-level intelligent discovery tools for ${this.discoveredServices.length} services`);

        // Level 1: Lightweight discovery - returns minimal service/entity list for LLM decision
        this.mcpServer.registerTool(
            "discover-sap-data",
            {
                title: "Level 1: Discover SAP Services and Entities",
                description: "[LEVEL 1 - DISCOVERY] Search for SAP services and entities. Returns MINIMAL data (serviceId, serviceName, entityName) optimized for LLM decision making. If query matches, returns relevant results. If NO matches found, returns ALL available services with entities. After this call, use get-entity-metadata (Level 2) to get full schema details for your selected entity. Uses technical user (no auth needed).",
                inputSchema: {
                    query: z.string().optional().describe("Search term to find services or entities. Searches service names, entity names. Examples: 'customer', 'sales order', 'employee'. If omitted or no matches found, returns ALL services with their entities (minimal fields only)."),
                    category: z.string().optional().describe("Service category filter. Valid values: business-partner, sales, finance, procurement, hr, logistics, all. Default: all. Narrows search to specific business area."),
                    limit: z.number().min(1).max(50).optional().describe("Maximum number of results. Default: 20. Use higher limits when returning all services.")
                }
            },
            async (args: Record<string, unknown>) => {
                return this.discoverServicesAndEntitiesMinimal(args);
            }
        );

        // Level 2: Get full entity metadata for selected service/entity
        this.mcpServer.registerTool(
            "get-entity-metadata",
            {
                title: "Level 2: Get Entity Metadata",
                description: "[LEVEL 2 - METADATA] Get complete schema details for a specific entity. Returns ALL properties with types, keys, nullable flags, maxLength, and capabilities (creatable, updatable, deletable). Use this after discover-sap-data to get full details needed for execute-sap-operation. Uses technical user (no auth needed).",
                inputSchema: {
                    serviceId: z.string().describe("Service ID from discover-sap-data results. Use the 'serviceId' field exactly as returned."),
                    entityName: z.string().describe("Entity name from discover-sap-data results. Use the 'entityName' field exactly as returned.")
                }
            },
            async (args: Record<string, unknown>) => {
                return this.getEntityMetadataFull(args);
            }
        );

        // Level 3: Execute operations on entities
        this.mcpServer.registerTool(
            "execute-sap-operation",
            {
                title: "Level 3: Execute SAP Operation",
                description: "[LEVEL 3 - EXECUTION] AUTHENTICATION REQUIRED: Perform CRUD operations on SAP entities using authenticated user context. Requires valid JWT token for authorization. Use get-entity-metadata (Level 2) first to understand entity schema, then call this to execute operations. Operations execute under user's SAP identity with full audit trail.",
                inputSchema: {
                    serviceId: z.string().describe("The SAP service ID from discover-sap-data. IMPORTANT: Use the 'id' field from the search results, NOT the 'title' field."),
                    entityName: z.string().describe("The entity name from discover-sap-data. IMPORTANT: Use the 'name' field from the results, NOT the 'entitySet' field."),
                    operation: z.string().describe("The operation to perform. Valid values: read, read-single, create, update, patch, delete. 'patch' is identical to 'update' (both send HTTP PATCH). For draft-enabled entities with IsActiveEntity keys, prefer the dedicated patch-sap-entity tool."),
                    parameters: z.record(z.any()).optional().describe("Operation parameters such as keys, filters, and data. For read-single/update/delete operations, include the entity key properties. For create/update operations, include the entity data fields."),
                    filterString: z.string().optional().describe("OData $filter query option value. Use OData filter syntax without the '$filter=' prefix. Examples: \"Status eq 'Active'\", \"Amount gt 1000\", \"Name eq 'John' and Status eq 'Active'\". Common operators: eq (equals), ne (not equals), gt (greater than), lt (less than), ge (greater/equal), le (less/equal), and, or, not."),
                    selectString: z.string().optional().describe("OData $select query option value. Comma-separated list of property names to include in the response, without the '$select=' prefix. Example: \"Name,Status,CreatedDate\" or \"CustomerID,CustomerName\". WARNING: Not all SAP OData APIs fully support $select. If the operation fails with a $select-related error, retry WITHOUT this parameter to get all properties."),
                    expandString: z.string().optional().describe("OData $expand query option value. Comma-separated list of navigation properties to expand, without the '$expand=' prefix. Example: \"Customer,Items\" or \"OrderDetails\"."),
                    orderbyString: z.string().optional().describe("OData $orderby query option value. Specify property name and direction (asc/desc), without the '$orderby=' prefix. Examples: \"Name desc\", \"CreatedDate asc\", \"Amount desc, Name asc\"."),
                    topNumber: z.number().optional().describe("OData $top query option value. Number of records to return (limit/page size). This will be converted to the $top parameter. Example: 10 returns top 10 records."),
                    skipNumber: z.number().optional().describe("OData $skip query option value. Number of records to skip (offset for pagination). This will be converted to the $skip parameter. Example: 20 skips first 20 records."),
                    useUserToken: z.boolean().optional().describe("Use the authenticated user's token for this operation. Default: true for data operations")
                }
            },
            async (args: Record<string, unknown>) => {
                return this.executeEntityOperation(args);
            }
        );

        // Tool 4: Execute Function Import / Action (SAP Draft API, business operations)
        this.mcpServer.registerTool(
            "execute-function-import",
            {
                title: "Execute SAP OData Function Import or Action",
                description: `[LEVEL 3 - EXECUTION] Execute an OData Function Import or Action on a SAP service. AUTHENTICATION REQUIRED. Use for: draft lifecycle operations (EditAction, ActivationAction, DiscardAction), business actions (AssignSourceOfSupply, CreatePurchaseOrder, CreateRFQ), or any named operation that appears in the service $metadata under <FunctionImport> or <Action>. For entity-bound actions, provide the full entityPath including key predicates. For unbound actions, omit entityPath and pass all parameters in the 'parameters' field. Use get-service-metadata with format 'function-imports-only' to discover available function imports first.`,
                inputSchema: {
                    serviceId: z.string().describe("SAP service ID from discover-sap-data, e.g. 'ZMM_PUR_PR_PROCESS_SRV_0001'"),
                    functionName: z.string().describe("The exact function import name as it appears in $metadata, e.g. 'EditAction', 'ActivationAction', 'DiscardAction', 'AssignSourceOfSupply'. Do NOT include the namespace prefix — that is added automatically."),
                    entityPath: z.string().optional().describe("Optional. Full entity path including key predicates to bind the action to a specific record. e.g. \"C_Purchasereqitmdtlsext(PurchaseRequisition='10000000',PurchaseRequisitionItem='00010',IsActiveEntity=true)\". Omit for unbound/service-level function imports."),
                    parameters: z.record(z.any()).optional().describe("Key-value pairs of function import input parameters. For bound actions these are sent in the POST body. For unbound GET functions these are appended as query string parameters. Example: { PreserveChanges: false }"),
                    httpMethod: z.enum(["GET", "POST"]).optional().describe("HTTP method to use. Default: POST. Most SAP actions use POST; some read-only functions use GET. Check get-service-metadata if unsure."),
                    returnEntitySet: z.string().optional().describe("Optional. The entity set name the function import returns, used to parse the response correctly. Found in the EntitySet attribute of the FunctionImport in $metadata.")
                }
            },
            async (args: Record<string, unknown>) => {
                return this.executeFunctionImport(args);
            }
        );

        // Tool 5: PATCH entity with composite keys (incl. IsActiveEntity for SAP Draft API)
        this.mcpServer.registerTool(
            "patch-sap-entity",
            {
                title: "Partially Update (PATCH) a SAP Entity",
                description: `[LEVEL 3 - EXECUTION] Partially update (PATCH) a specific SAP entity record. AUTHENTICATION REQUIRED. Use this instead of the standard 'update' operation when: the entity has an 'IsActiveEntity' key (draft-enabled services — always set to false to patch the draft); you only want to update specific fields without sending the full entity; or the standard update operation returns an error on partial payloads. This is the correct way to update draft entity fields before calling ActivationAction. Tip: run execute-function-import with functionName='EditAction' first to create the draft, then patch it here, then activate with ActivationAction.`,
                inputSchema: {
                    serviceId: z.string().describe("SAP service ID from discover-sap-data"),
                    entityName: z.string().describe("Entity type name as returned by discover-sap-data or get-entity-metadata (e.g. 'C_PurchasereqitmdtlsextType'). Used to look up the entity set name."),
                    keyProperties: z.record(z.any()).describe("All key fields needed to identify the specific record. For draft entities include IsActiveEntity: false to target the draft. Example: { PurchaseRequisition: '10000000', PurchaseRequisitionItem: '00010', IsActiveEntity: false }. Boolean and numeric values must be passed as native types (not strings) so they are formatted correctly in the OData key predicate."),
                    updateFields: z.record(z.any()).describe("Only the fields you want to change. Example: { PurchaseRequisitionItemText: 'New description', RequestedQuantity: 5 }")
                }
            },
            async (args: Record<string, unknown>) => {
                return this.patchSapEntity(args);
            }
        );

        // Tool 6: Get service $metadata (including function imports and nav properties)
        this.mcpServer.registerTool(
            "get-service-metadata",
            {
                title: "Get SAP Service OData Metadata",
                description: `Retrieve the OData $metadata for a SAP service, exposing information not available through the standard entity tools. Returns: all Function Imports and their parameters (operations not available via CRUD); navigation properties (relationships between entities); entity key properties; draft-enabled indicators. Use 'function-imports-only' format to discover what actions exist before calling execute-function-import. Uses technical user (no auth needed).`,
                inputSchema: {
                    serviceId: z.string().describe("SAP service ID from discover-sap-data"),
                    format: z.enum(["summary", "full-xml", "function-imports-only", "navigation-properties-only"])
                        .optional()
                        .describe("How to return the metadata. 'summary' (default) returns a structured JSON overview. 'full-xml' returns raw $metadata XML. 'function-imports-only' returns just the function imports with parameters. 'navigation-properties-only' returns just nav props per entity.")
                }
            },
            async (args: Record<string, unknown>) => {
                return this.getServiceMetadata(args);
            }
        );

        this.logger.info("✅ Registered 3-level intelligent discovery tools successfully");
    }

    /**
     * Categorize services for better discovery using intelligent pattern matching
     */
    private categorizeServices(): void {
        for (const service of this.discoveredServices) {
            const categories: string[] = [];
            const id = service.id.toLowerCase();
            const title = service.title.toLowerCase();
            const desc = service.description.toLowerCase();

            // Business Partner related
            if (id.includes('business_partner') || id.includes('bp_') || id.includes('customer') || id.includes('supplier') ||
                title.includes('business partner') || title.includes('customer') || title.includes('supplier')) {
                categories.push('business-partner');
            }

            // Sales related
            if (id.includes('sales') || id.includes('order') || id.includes('quotation') || id.includes('opportunity') ||
                title.includes('sales') || title.includes('order') || desc.includes('sales')) {
                categories.push('sales');
            }

            // Finance related
            if (id.includes('finance') || id.includes('accounting') || id.includes('payment') || id.includes('invoice') ||
                id.includes('gl_') || id.includes('ar_') || id.includes('ap_') || title.includes('finance') ||
                title.includes('accounting') || title.includes('payment')) {
                categories.push('finance');
            }

            // Procurement related
            if (id.includes('purchase') || id.includes('procurement') || id.includes('vendor') || id.includes('po_') ||
                title.includes('procurement') || title.includes('purchase') || title.includes('vendor')) {
                categories.push('procurement');
            }

            // HR related
            if (id.includes('employee') || id.includes('hr_') || id.includes('personnel') || id.includes('payroll') ||
                title.includes('employee') || title.includes('human') || title.includes('personnel')) {
                categories.push('hr');
            }

            // Logistics related
            if (id.includes('logistics') || id.includes('warehouse') || id.includes('inventory') || id.includes('material') ||
                id.includes('wm_') || id.includes('mm_') || title.includes('logistics') || title.includes('material')) {
                categories.push('logistics');
            }

            // Default category if none matched
            if (categories.length === 0) {
                categories.push('all');
            }

            this.serviceCategories.set(service.id, categories);
        }

        this.logger.debug(`Categorized ${this.discoveredServices.length} services into categories`);
    }

    /**
     * Level 1: Lightweight discovery - returns minimal service/entity list
     * Optimized for LLM token efficiency with only essential fields
     *
     * Returns:
     * - If query matches: Relevant services/entities with minimal fields
     * - If no matches: ALL services with entities (minimal fields)
     * - Fields returned: serviceId, serviceName, entityName, entityCount, categories
     */
    private async discoverServicesAndEntitiesMinimal(args: Record<string, unknown>) {
        try {
            const query = (args.query as string)?.toLowerCase() || "";
            const requestedCategory = (args.category as string)?.toLowerCase() || "all";
            const limit = (args.limit as number) || 20;

            // Validate category
            const validCategories = ["business-partner", "sales", "finance", "procurement", "hr", "logistics", "all"];
            let category = validCategories.includes(requestedCategory) ? requestedCategory : "all";

            let matches: any[] = [];
            let returnedAllServices = false;

            // Try to find matches
            matches = this.performMinimalSearch(query, category);

            // If no matches found, return ALL services with minimal data
            if (matches.length === 0 && query) {
                this.logger.debug(`No results found for query '${query}', returning all available services (minimal)`);
                matches = this.performMinimalSearch("", category);
                returnedAllServices = true;
            }

            // Sort by relevance score (if searching) or alphabetically (if returning all)
            if (!returnedAllServices && query) {
                matches.sort((a, b) => b.score - a.score);
            } else {
                matches.sort((a, b) => {
                    if (a.type === 'service' && b.type === 'service') {
                        return a.service.serviceName.localeCompare(b.service.serviceName);
                    }
                    return 0;
                });
            }

            // Apply limit
            const totalFound = matches.length;
            const limitedMatches = matches.slice(0, limit);

            const result = {
                query: query || "all",
                category: category,
                returnedAllServices: returnedAllServices,
                totalFound: totalFound,
                showing: limitedMatches.length,
                matches: limitedMatches
            };

            // Build response
            let responseText = "";

            if (returnedAllServices) {
                responseText += `[LEVEL 1 - NO MATCHES] No results found for "${query}". Returning ALL available services and entities.\n\n`;
            } else if (query) {
                responseText += `[LEVEL 1 - SEARCH RESULTS] Found ${totalFound} matches for "${query}"\n\n`;
            } else {
                responseText += `[LEVEL 1 - ALL SERVICES] Showing all available services and entities\n\n`;
            }

            responseText += `NEXT STEP: Select a service and entity from the results below, then call get-entity-metadata\n`;
            responseText += `  with the serviceId and entityName to get full schema details.\n\n`;
            responseText += `Results (showing ${limitedMatches.length} of ${totalFound}):\n\n`;
            responseText += JSON.stringify(result, null, 2);

            return {
                content: [{
                    type: "text" as const,
                    text: responseText
                }]
            };

        } catch (error) {
            this.logger.error('Error in Level 1 discovery:', error);
            return {
                content: [{
                    type: "text" as const,
                    text: `ERROR: ${error instanceof Error ? error.message : String(error)}`
                }],
                isError: true
            };
        }
    }

    /**
     * Level 2: Get full entity metadata for a specific service and entity
     * Returns complete schema with all properties, types, keys, and capabilities
     */
    private async getEntityMetadataFull(args: Record<string, unknown>) {
        try {
            const serviceId = args.serviceId as string;
            const entityName = args.entityName as string;

            if (!serviceId || !entityName) {
                return {
                    content: [{
                        type: "text" as const,
                        text: `ERROR: Both serviceId and entityName are required.\n\nUsage: Call discover-sap-data first, then use the serviceId and entityName from those results.`
                    }],
                    isError: true
                };
            }

            // Find the service
            const service = this.discoveredServices.find(s => s.id === serviceId);
            if (!service) {
                return {
                    content: [{
                        type: "text" as const,
                        text: `ERROR: Service not found: ${serviceId}\n\nUse discover-sap-data to find available services.`
                    }],
                    isError: true
                };
            }

            // Find the entity
            const entityType = service.metadata?.entityTypes?.find(e => e.name === entityName);
            if (!entityType) {
                const availableEntities = service.metadata?.entityTypes?.map(e => e.name).join(', ') || 'none';
                return {
                    content: [{
                        type: "text" as const,
                        text: `ERROR: Entity '${entityName}' not found in service '${serviceId}'\n\nAvailable entities: ${availableEntities}`
                    }],
                    isError: true
                };
            }

            // Build complete metadata response
            const metadata = {
                service: {
                    serviceId: service.id,
                    serviceName: service.title,
                    description: service.description,
                    odataVersion: service.odataVersion
                },
                entity: {
                    name: entityType.name,
                    entitySet: entityType.entitySet,
                    namespace: entityType.namespace,
                    keyProperties: entityType.keys,
                    propertyCount: entityType.properties.length
                },
                capabilities: {
                    readable: true,
                    creatable: entityType.creatable,
                    updatable: entityType.updatable,
                    deletable: entityType.deletable
                },
                properties: entityType.properties.map(prop => ({
                    name: prop.name,
                    type: prop.type,
                    nullable: prop.nullable,
                    maxLength: prop.maxLength,
                    isKey: entityType.keys.includes(prop.name)
                }))
            };

            let responseText = `[LEVEL 2 - ENTITY METADATA] Complete schema for ${entityName} in ${service.title}\n\n`;
            responseText += `NEXT STEP: Use execute-sap-operation with:\n`;
            responseText += `  - serviceId: "${serviceId}"\n`;
            responseText += `  - entityName: "${entityName}"\n`;
            responseText += `  - operation: read | read-single | create | update | delete\n`;
            responseText += `  - Use the properties below to construct parameters\n\n`;
            responseText += `Key Properties: [${entityType.keys.join(', ')}]\n`;
            responseText += `Capabilities: creatable=${entityType.creatable}, updatable=${entityType.updatable}, deletable=${entityType.deletable}\n\n`;
            responseText += `Full Metadata:\n\n`;
            responseText += JSON.stringify(metadata, null, 2);

            return {
                content: [{
                    type: "text" as const,
                    text: responseText
                }]
            };

        } catch (error) {
            this.logger.error('Error in Level 2 metadata retrieval:', error);
            return {
                content: [{
                    type: "text" as const,
                    text: `ERROR: ${error instanceof Error ? error.message : String(error)}`
                }],
                isError: true
            };
        }
    }

    /**
     * Perform minimal search across services and entities
     * Returns only essential fields: serviceId, serviceName, entityName
     * Optimized for LLM token efficiency
     */
    private performMinimalSearch(query: string, category: string): Array<{
        type: 'service' | 'entity';
        score: number;
        service: {
            serviceId: string;
            serviceName: string;
            entityCount: number;
            categories: string[];
        };
        entities?: Array<{
            entityName: string;
        }>;
        entity?: {
            entityName: string;
        };
        matchReason?: string;
    }> {
        const matches: Array<any> = [];

        // Search across all services
        for (const service of this.discoveredServices) {
            // Filter by category first
            if (category !== "all") {
                const serviceCategories = this.serviceCategories.get(service.id) || [];
                if (!serviceCategories.includes(category)) {
                    continue;
                }
            }

            const serviceIdLower = service.id.toLowerCase();
            const serviceTitleLower = service.title.toLowerCase();

            // Service-level match
            let serviceScore = 0;
            if (query) {
                if (serviceIdLower.includes(query)) serviceScore = 0.9;
                else if (serviceTitleLower.includes(query)) serviceScore = 0.85;
            }

            // If service matches or no query, include service with minimal entity list
            if (serviceScore > 0 || !query) {
                const entities = service.metadata?.entityTypes?.map(entity => ({
                    entityName: entity.name
                })) || [];

                matches.push({
                    type: "service",
                    score: serviceScore || 0.5,
                    service: {
                        serviceId: service.id,
                        serviceName: service.title,
                        entityCount: entities.length,
                        categories: this.serviceCategories.get(service.id) || []
                    },
                    entities: entities,
                    matchReason: serviceScore > 0 ? `Service matches '${query}'` : `Service in category '${category}'`
                });
            }

            // Entity-level matches within this service (only if query provided)
            if (service.metadata?.entityTypes && query) {
                for (const entity of service.metadata.entityTypes) {
                    const entityNameLower = entity.name.toLowerCase();

                    // Match entity name
                    if (entityNameLower.includes(query)) {
                        matches.push({
                            type: "entity",
                            score: 0.95,
                            service: {
                                serviceId: service.id,
                                serviceName: service.title,
                                entityCount: service.metadata.entityTypes.length,
                                categories: this.serviceCategories.get(service.id) || []
                            },
                            entity: {
                                entityName: entity.name
                            },
                            matchReason: `Entity '${entity.name}' matches '${query}'`
                        });
                    }
                }
            }
        }

        return matches;
    }

    /**
     * Helper method to check if text matches query (supports multi-word queries)
     * Returns true if:
     * - Single word: text contains the word
     * - Multiple words separated: text contains ALL words
     */
    private matchesQuery(text: string, query: string, searchMode: 'combined' | 'separated'): boolean {
        if (!query) return false;

        const textLower = text.toLowerCase();

        if (searchMode === 'combined') {
            // Try as combined query (e.g., "userparameters")
            return textLower.includes(query);
        } else {
            // Try as separated words (e.g., "user" AND "parameters")
            const words = query.split(/\s+/).filter(w => w.length > 0);
            if (words.length === 0) return false;
            if (words.length === 1) return textLower.includes(words[0]);

            // All words must be present
            return words.every(word => textLower.includes(word));
        }
    }

    /**
     * Helper method to perform search across services and entities for a given category
     * Extracts common search logic to avoid duplication in fallback scenario
     * Supports multi-word queries with intelligent matching
     */
    private performCategorySearch(query: string, category: string, searchMode: 'combined' | 'separated' = 'combined'): any[] {
        const matches: any[] = [];

        // Search across all services
        for (const service of this.discoveredServices) {
            // Filter by category first
            if (category !== "all") {
                const serviceCategories = this.serviceCategories.get(service.id) || [];
                if (!serviceCategories.includes(category)) {
                    continue;
                }
            }

            const serviceIdLower = service.id.toLowerCase();
            const serviceTitleLower = service.title.toLowerCase();
            const serviceDescLower = service.description.toLowerCase();

            // Service-level match with multi-word support
            let serviceScore = 0;
            if (query) {
                if (this.matchesQuery(serviceIdLower, query, searchMode)) serviceScore = 0.9;
                else if (this.matchesQuery(serviceTitleLower, query, searchMode)) serviceScore = 0.85;
                else if (this.matchesQuery(serviceDescLower, query, searchMode)) serviceScore = 0.7;
            }

            if (serviceScore > 0 || !query) {
                // Always include full entity schemas even for service-level matches
                const entities = service.metadata?.entityTypes?.map(entity => ({
                    name: entity.name,
                    entitySet: entity.entitySet,
                    keyProperties: entity.keys,
                    propertyCount: entity.properties.length,
                    capabilities: {
                        readable: true,
                        creatable: entity.creatable,
                        updatable: entity.updatable,
                        deletable: entity.deletable
                    },
                    properties: entity.properties.map(prop => ({
                        name: prop.name,
                        type: prop.type,
                        nullable: prop.nullable,
                        maxLength: prop.maxLength,
                        isKey: entity.keys.includes(prop.name)
                    }))
                })) || [];

                matches.push({
                    type: "service",
                    score: serviceScore || 0.5,
                    service: {
                        id: service.id,
                        title: service.title,
                        description: service.description,
                        entityCount: service.metadata?.entityTypes?.length || 0,
                        categories: this.serviceCategories.get(service.id) || []
                    },
                    // Include all entities with full schemas
                    entities: entities,
                    matchReason: serviceScore > 0 ? `Service matches '${query}'` : `Service in category '${category}'`
                });
            }

            // Entity-level matches within this service
            if (service.metadata?.entityTypes && query) {
                for (const entity of service.metadata.entityTypes) {
                    const entityNameLower = entity.name.toLowerCase();
                    let entityScore = 0;

                    // Match entity name with multi-word support
                    if (this.matchesQuery(entityNameLower, query, searchMode)) {
                        entityScore = 0.95;
                    }

                    // Match property names with multi-word support
                    let matchedProperties: string[] = [];
                    for (const prop of entity.properties) {
                        if (this.matchesQuery(prop.name.toLowerCase(), query, searchMode)) {
                            matchedProperties.push(prop.name);
                            if (entityScore === 0) entityScore = 0.75;
                        }
                    }

                    if (entityScore > 0) {
                        const match: any = {
                            type: entityScore >= 0.9 ? "entity" : "property",
                            score: entityScore,
                            service: {
                                id: service.id,
                                title: service.title
                            },
                            entity: {
                                name: entity.name,
                                entitySet: entity.entitySet,
                                keyProperties: entity.keys,
                                propertyCount: entity.properties.length,
                                capabilities: {
                                    readable: true,
                                    creatable: entity.creatable,
                                    updatable: entity.updatable,
                                    deletable: entity.deletable
                                },
                                // Always include full schema for maximum efficiency
                                properties: entity.properties.map(prop => ({
                                    name: prop.name,
                                    type: prop.type,
                                    nullable: prop.nullable,
                                    maxLength: prop.maxLength,
                                    isKey: entity.keys.includes(prop.name)
                                }))
                            },
                            matchReason: entityScore >= 0.9
                                ? `Entity '${entity.name}' matches '${query}'`
                                : `Properties [${matchedProperties.join(', ')}] match '${query}'`
                        };

                        matches.push(match);
                    }
                }
            }
        }

        return matches;
    }

    /**
     * Intelligent search across services, entities, and properties
     * Always returns full schemas for maximum efficiency (avoids second requests)
     * Multi-word query support with intelligent 3-level fallback:
     * 1. Try combined words with requested category
     * 2. If no results: try separated words with requested category
     * 3. If still no results with specific category: try with 'all' categories
     * 4. If still no results: try separated words with 'all' categories
     */
    private async searchServicesAndEntities(args: Record<string, unknown>) {
        try {
            const query = (args.query as string)?.toLowerCase() || "";
            const requestedCategory = (args.category as string)?.toLowerCase() || "all";
            const limit = (args.limit as number) || 10;

            // Validate category
            const validCategories = ["business-partner", "sales", "finance", "procurement", "hr", "logistics", "all"];
            let category = validCategories.includes(requestedCategory) ? requestedCategory : "all";

            let matches: any[] = [];
            let searchMode: 'combined' | 'separated' = 'combined';
            let usedCategoryFallback = false;
            let usedSeparatedWords = false;
            let returnedAllServices = false;

            // Level 1: Try combined words with requested category
            matches = this.performCategorySearch(query, category, 'combined');

            // Level 2: If no results and multi-word query, try separated words with same category
            if (matches.length === 0 && query && query.includes(' ')) {
                this.logger.debug(`No results with combined query, trying separated words in category '${category}'`);
                searchMode = 'separated';
                usedSeparatedWords = true;
                matches = this.performCategorySearch(query, category, 'separated');
            }

            // Level 3: If still no results with specific category, try with 'all'
            if (matches.length === 0 && category !== "all" && query) {
                this.logger.debug(`No results in category '${category}', retrying with 'all' categories`);
                category = "all";
                usedCategoryFallback = true;

                // Try combined first
                matches = this.performCategorySearch(query, category, 'combined');
                searchMode = 'combined';
                usedSeparatedWords = false;

                // Level 4: If still no results and multi-word, try separated with 'all'
                if (matches.length === 0 && query.includes(' ')) {
                    this.logger.debug(`No results with combined query in 'all', trying separated words`);
                    searchMode = 'separated';
                    usedSeparatedWords = true;
                    matches = this.performCategorySearch(query, category, 'separated');
                }
            }

            // Level 5: If still no results after all attempts, return ALL services with full schemas
            if (matches.length === 0 && query) {
                this.logger.debug(`No results found for query '${query}', returning all available services with full schemas`);
                // Return all services with complete entity schemas
                matches = this.performCategorySearch("", category, 'combined');
                returnedAllServices = true;
                usedCategoryFallback = true;
            }

            // Sort by relevance score
            matches.sort((a, b) => b.score - a.score);

            // Apply limit
            const totalFound = matches.length;
            const limitedMatches = matches.slice(0, limit);

            const result = {
                query: query || "all",
                requestedCategory: requestedCategory,
                actualCategory: category,
                searchMode: searchMode,
                usedCategoryFallback: usedCategoryFallback,
                usedSeparatedWords: usedSeparatedWords,
                returnedAllServices: returnedAllServices,
                totalFound: totalFound,
                showing: limitedMatches.length,
                detailLevel: "full",
                matches: limitedMatches
            };

            // Build response with GUIDANCE FIRST, then data
            let responseText = "";

            if (limitedMatches.length > 0) {
                responseText += `*** DISCOVERY COMPLETE - YOU HAVE EVERYTHING YOU NEED! ***\n\n`;
                responseText += `[COMPLETE] This response contains COMPLETE entity schemas with ALL properties, types, keys, and capabilities\n`;
                responseText += `[STOP] NO additional discovery needed - Do NOT call discover-sap-data again\n`;
                responseText += `[NEXT] Use execute-sap-operation immediately with the data below\n\n`;
                if (returnedAllServices) {
                    responseText += `NOTICE: No matches found for "${query}", so returning ALL available services with full schemas\n\n`;
                }
                responseText += `SUMMARY: Found ${totalFound} matches`;
                if (query && !returnedAllServices) responseText += ` for "${query}"`;
                if (requestedCategory !== "all") responseText += ` in category "${requestedCategory}"`;
                if (usedCategoryFallback && !returnedAllServices) responseText += ` (searched all categories)`;
                if (usedSeparatedWords) responseText += ` (matched separated words)`;
                responseText += `, showing ${limitedMatches.length}\n\n`;
                responseText += `EXECUTE WITH THESE VALUES:\n`;
                responseText += `  serviceId: "${limitedMatches[0].service.id}" (from 'service.id' in results)\n`;
                if (limitedMatches[0].type === 'entity' || limitedMatches[0].type === 'property') {
                    responseText += `  entityName: "${limitedMatches[0].entity.name}" (from 'entity.name' in results)\n`;
                }
                responseText += `  operation: read | read-single | create | update | delete\n\n`;
                responseText += `================================================\n`;
                responseText += `FULL DATA (complete schemas with all details):\n`;
                responseText += `================================================\n\n`;
                responseText += JSON.stringify(result, null, 2);
            } else {
                responseText += `No matches found`;
                if (query) responseText += ` for "${query}"`;
                if (requestedCategory !== "all") responseText += ` in category "${requestedCategory}"`;
                responseText += `\n\n== SUGGESTION ==`;
                responseText += `\nTry different search terms or categories: business-partner, sales, finance, procurement, hr, logistics, all`;
            }

            return {
                content: [{
                    type: "text" as const,
                    text: responseText
                }]
            };

        } catch (error) {
            this.logger.error('Error searching services and entities:', error);
            return {
                content: [{
                    type: "text" as const,
                    text: `Error searching: ${error instanceof Error ? error.message : String(error)}`
                }],
                isError: true
            };
        }
    }

    /**
     * Legacy search services method (kept for backward compatibility)
     */
    private async searchServices(args: Record<string, unknown>) {
        try {
            const query = (args.query as string)?.toLowerCase() || "";
            let category = (args.category as string)?.toLowerCase() || "all";
            const limit = (args.limit as number) || 10;

            // Validate category for better Copilot compatibility
            const validCategories = ["business-partner", "sales", "finance", "procurement", "hr", "logistics", "all"];
            if (!validCategories.includes(category)) {
                category = "all"; // Default to 'all' if invalid category provided
            }

            let filteredServices = this.discoveredServices;

            // Filter by category first
            if (category && category !== "all") {
                filteredServices = filteredServices.filter(service =>
                    this.serviceCategories.get(service.id)?.includes(category)
                );
            }

            // Filter by search query
            if (query) {
                filteredServices = filteredServices.filter(service =>
                    service.id.toLowerCase().includes(query) ||
                    service.title.toLowerCase().includes(query) ||
                    service.description.toLowerCase().includes(query)
                );
            }

            // Apply limit
            const totalFound = filteredServices.length;
            filteredServices = filteredServices.slice(0, limit);

            const result = {
                query: query || "all",
                category: category,
                totalFound: totalFound,
                showing: filteredServices.length,
                services: filteredServices.map(service => ({
                    id: service.id,
                    title: service.title,
                    description: service.description,
                    entityCount: service.metadata?.entityTypes?.length || 0,
                    categories: this.serviceCategories.get(service.id) || [],
                    version: service.version,
                    odataVersion: service.odataVersion
                }))
            };

            let responseText = `Found ${totalFound} SAP services`;
            if (query) responseText += ` matching "${query}"`;
            if (category !== "all") responseText += ` in category "${category}"`;
            responseText += `:\n\n${JSON.stringify(result, null, 2)}`;

            if (result.services.length > 0) {
                responseText += `\n\n== NEXT STEPS ==`;
                responseText += `\n1. Call 'discover-sap-data' with serviceId parameter to see entities within a service`;
                responseText += `\n2. Set serviceId to the 'id' field from the results above`;
                responseText += `\n3. IMPORTANT: Use the 'id' field as serviceId, NOT the 'title' field`;
            } else {
                responseText += `\n\n== SUGGESTION ==`;
                responseText += `\nTry different search terms or categories: business-partner, sales, finance, procurement, hr, logistics, all`;
            }

            return {
                content: [{
                    type: "text" as const,
                    text: responseText
                }]
            };

        } catch (error) {
            this.logger.error('Error searching services:', error);
            return {
                content: [{
                    type: "text" as const,
                    text: `Error searching services: ${error instanceof Error ? error.message : String(error)}`
                }],
                isError: true
            };
        }
    }

    /**
     * Discover entities within a service with full schemas
     * Always returns complete property details for maximum efficiency
     *
     * NOTE: This method is kept for potential future use but is NOT exposed via the tool interface.
     * The query-based search already returns full schemas, making this redundant.
     */
    private async discoverServiceEntities(args: Record<string, unknown>) {
        try {
            const serviceId = args.serviceId as string;

            const service = this.discoveredServices.find(s => s.id === serviceId);
            if (!service) {
                // Check if user provided a title instead of an id
                const serviceByTitle = this.discoveredServices.find(s => s.title.toLowerCase() === serviceId.toLowerCase());
                let errorMessage = `ERROR: Service not found: ${serviceId}\n\n`;

                if (serviceByTitle) {
                    errorMessage += `WARNING: It looks like you used the 'title' field instead of the 'id' field!\n`;
                    errorMessage += `CORRECTION: Use this serviceId instead: ${serviceByTitle.id}\n\n`;
                    errorMessage += `Remember: Always use the 'id' field from discover-sap-data results, NOT the 'title' field.`;
                } else {
                    errorMessage += `SUGGESTION: Use 'discover-sap-data' to find available services.\n`;
                    errorMessage += `REMINDER: Make sure you're using the 'id' field from search results, NOT the 'title' field.`;
                }

                return {
                    content: [{
                        type: "text" as const,
                        text: errorMessage
                    }],
                    isError: true
                };
            }

            if (!service.metadata?.entityTypes) {
                return {
                    content: [{
                        type: "text" as const,
                        text: `WARNING: No entities found for service: ${serviceId}. The service metadata may not have loaded properly.`
                    }]
                };
            }

            // Always include full schemas for maximum efficiency
            const entities = service.metadata.entityTypes.map(entity => ({
                name: entity.name,
                entitySet: entity.entitySet,
                keyProperties: entity.keys,
                propertyCount: entity.properties.length,
                capabilities: {
                    readable: true, // Always true for OData
                    creatable: entity.creatable,
                    updatable: entity.updatable,
                    deletable: entity.deletable
                },
                // Include full property schemas
                properties: entity.properties.map(prop => ({
                    name: prop.name,
                    type: prop.type,
                    nullable: prop.nullable,
                    maxLength: prop.maxLength,
                    isKey: entity.keys.includes(prop.name)
                }))
            }));

            const serviceInfo = {
                service: {
                    id: serviceId,
                    title: service.title,
                    description: service.description,
                    categories: this.serviceCategories.get(service.id) || [],
                    odataVersion: service.odataVersion
                },
                detailLevel: "full",
                entities: entities
            };

            let responseText = `Service: ${service.title} (${serviceId})\n`;
            responseText += `Found ${entities.length} entities with full schemas\n\n`;
            responseText += JSON.stringify(serviceInfo, null, 2);
            responseText += `\n\n== READY TO EXECUTE ==\n`;
            responseText += `✓ COMPLETE SCHEMAS INCLUDED - All ${entities.length} entity schemas with properties, types, keys, and capabilities are already in the results above\n`;
            responseText += `✓ NO ADDITIONAL DISCOVERY NEEDED - Do NOT call discover-sap-data again\n`;
            responseText += `✓ EXECUTE IMMEDIATELY - Use execute-sap-operation now with:\n`;
            responseText += `  - serviceId: "${serviceId}"\n`;
            responseText += `  - entityName: Use the 'name' field from entity above (NOT 'entitySet')\n`;
            responseText += `  - operation: read, read-single, create, update, or delete\n`;
            responseText += `  - parameters: Use the property names shown in the schemas above`;

            return {
                content: [{
                    type: "text" as const,
                    text: responseText
                }]
            };

        } catch (error) {
            this.logger.error('Error discovering service entities:', error);
            return {
                content: [{
                    type: "text" as const,
                    text: `ERROR: Failed to discover entities: ${error instanceof Error ? error.message : String(error)}`
                }],
                isError: true
            };
        }
    }

    /**
     * Get detailed entity schema information
     *
     * NOTE: This method is kept for potential future use but is NOT exposed via the tool interface.
     * The query-based search already returns full schemas, making this redundant.
     */
    private async getEntitySchema(args: Record<string, unknown>) {
        try {
            const serviceId = args.serviceId as string;
            const entityName = args.entityName as string;

            const service = this.discoveredServices.find(s => s.id === serviceId);
            if (!service) {
                // Check if user provided a title instead of an id
                const serviceByTitle = this.discoveredServices.find(s => s.title.toLowerCase() === serviceId.toLowerCase());
                let errorMessage = `ERROR: Service not found: ${serviceId}\n\n`;

                if (serviceByTitle) {
                    errorMessage += `WARNING: It looks like you used the 'title' field instead of the 'id' field!\n`;
                    errorMessage += `CORRECTION: Use this serviceId instead: ${serviceByTitle.id}\n\n`;
                    errorMessage += `Remember: Always use the 'id' field from discover-sap-data results, NOT the 'title' field.`;
                } else {
                    errorMessage += `SUGGESTION: Use 'discover-sap-data' to find available services.\n`;
                    errorMessage += `REMINDER: Make sure you're using the 'id' field from search results, NOT the 'title' field.`;
                }
                
                return {
                    content: [{
                        type: "text" as const,
                        text: errorMessage
                    }],
                    isError: true
                };
            }

            const entityType = service.metadata?.entityTypes?.find(e => e.name === entityName);
            if (!entityType) {
                const availableEntities = service.metadata?.entityTypes?.map(e => e.name).join(', ') || 'none';
                return {
                    content: [{
                        type: "text" as const,
                        text: `ERROR: Entity '${entityName}' not found in service '${serviceId}'\n\nAvailable entities: ${availableEntities}`
                    }],
                    isError: true
                };
            }

            const schema = {
                entity: {
                    name: entityType.name,
                    entitySet: entityType.entitySet,
                    namespace: entityType.namespace
                },
                capabilities: {
                    readable: true,
                    creatable: entityType.creatable,
                    updatable: entityType.updatable,
                    deletable: entityType.deletable
                },
                keyProperties: entityType.keys,
                properties: entityType.properties.map(prop => ({
                    name: prop.name,
                    type: prop.type,
                    nullable: prop.nullable,
                    maxLength: prop.maxLength,
                    isKey: entityType.keys.includes(prop.name)
                }))
            };

            let responseText = `Schema for ${entityName} in ${service.title}:\n\n`;
            responseText += JSON.stringify(schema, null, 2);
            responseText += `\n\n== READY TO EXECUTE ==`;
            responseText += `\n✓ COMPLETE SCHEMA INCLUDED - All properties, types, keys, and capabilities are already in the results above`;
            responseText += `\n✓ NO ADDITIONAL DISCOVERY NEEDED - Do NOT call discover-sap-data again`;
            responseText += `\n✓ EXECUTE IMMEDIATELY - Use execute-sap-operation now with:`;
            responseText += `\n  - serviceId: "${serviceId}"`;
            responseText += `\n  - entityName: "${entityName}"`;
            responseText += `\n  - operation: read, read-single, create, update, or delete`;
            responseText += `\n  - parameters: For operations, use keyProperties: [${entityType.keys.join(', ')}]`;
            responseText += `\n  - Check capabilities above: creatable=${entityType.creatable}, updatable=${entityType.updatable}, deletable=${entityType.deletable}`;

            return {
                content: [{
                    type: "text" as const,
                    text: responseText
                }]
            };

        } catch (error) {
            this.logger.error('Error getting entity schema:', error);
            return {
                content: [{
                    type: "text" as const,
                    text: `ERROR: Failed to get schema: ${error instanceof Error ? error.message : String(error)}`
                }],
                isError: true
            };
        }
    }

    /**
     * Execute CRUD operations on entities with comprehensive error handling
     */
    private async executeEntityOperation(args: Record<string, unknown>) {
        try {
            const serviceId = args.serviceId as string;
            const entityName = args.entityName as string;
            let operation = (args.operation as string)?.toLowerCase();
            const parameters = args.parameters as Record<string, unknown> || {};

            // Validate operation for better Copilot compatibility
            const validOperations = ["read", "read-single", "create", "update", "patch", "delete"];
            if (!validOperations.includes(operation)) {
                throw new Error(`Invalid operation: ${operation}. Valid operations are: ${validOperations.join(', ')}`);
            }
            // 'patch' is an alias for 'update' — both send HTTP PATCH
            if (operation === 'patch') operation = 'update';

            // Build queryOptions from flattened parameters for better Copilot compatibility
            const queryOptions: Record<string, unknown> = {};
            if (args.filterString) queryOptions.$filter = args.filterString;
            if (args.selectString) queryOptions.$select = args.selectString;
            if (args.expandString) queryOptions.$expand = args.expandString;
            if (args.orderbyString) queryOptions.$orderby = args.orderbyString;
            if (args.topNumber) queryOptions.$top = args.topNumber;
            if (args.skipNumber) queryOptions.$skip = args.skipNumber;

            // Also support legacy queryOptions object for backward compatibility
            if (args.queryOptions && typeof args.queryOptions === 'object') {
                Object.assign(queryOptions, args.queryOptions);
            }

            const useUserToken = args.useUserToken !== false; // Default to true

            // Validate service
            const service = this.discoveredServices.find(s => s.id === serviceId);
            if (!service) {
                // Check if user provided a title instead of an id
                const serviceByTitle = this.discoveredServices.find(s => s.title.toLowerCase() === serviceId.toLowerCase());
                let errorMessage = `ERROR: Service not found: ${serviceId}\n\n`;

                if (serviceByTitle) {
                    errorMessage += `WARNING: It looks like you used the 'title' field instead of the 'id' field!\n`;
                    errorMessage += `CORRECTION: Use this serviceId instead: ${serviceByTitle.id}\n\n`;
                    errorMessage += `Remember: Always use the 'id' field from discover-sap-data results, NOT the 'title' field.`;
                } else {
                    errorMessage += `SUGGESTION: Use 'discover-sap-data' to find available services.\n`;
                    errorMessage += `REMINDER: Make sure you're using the 'id' field from search results, NOT the 'title' field.`;
                }
                
                return {
                    content: [{
                        type: "text" as const,
                        text: errorMessage
                    }],
                    isError: true
                };
            }

            // Validate entity
            const entityType = service.metadata?.entityTypes?.find(e => e.name === entityName);
            if (!entityType) {
                return {
                    content: [{
                        type: "text" as const,
                        text: `ERROR: Entity '${entityName}' not found in service '${serviceId}'`
                    }],
                    isError: true
                };
            }

            // Permission check — verify the logged-in user may perform this operation
            const entitySetName = entityType.entitySet!;
            // TODO: Re-enable once Config App has entries populated
            // const permissionDenied = await this.enforcePermission(serviceId, entitySetName, operation);
            // if (permissionDenied) return permissionDenied;

            // Set user token if requested and available
            if (useUserToken && this.userToken) {
                this.sapClient.setUserToken(this.userToken);
            } else {
                this.sapClient.setUserToken(undefined);
            }

            // Execute the operation
            let response;
            let operationDescription = "";

            switch (operation) {
                case 'read':
                    operationDescription = `Reading ${entityName} entities`;
                    if (queryOptions.$top) operationDescription += ` (top ${queryOptions.$top})`;
                    if (queryOptions.$filter) operationDescription += ` with filter: ${queryOptions.$filter}`;

                    response = await this.sapClient.readEntitySet(service.url, entityType.entitySet!, queryOptions, false);
                    break;

                case 'read-single': {
                    const keyValue = this.buildKeyValue(entityType, parameters);
                    operationDescription = `Reading single ${entityName} with key: ${keyValue}`;
                    response = await this.sapClient.readEntity(service.url, entityType.entitySet!, keyValue, false);
                    break;
                }

                case 'create':
                    if (!entityType.creatable) {
                        throw new Error(`Entity '${entityName}' does not support create operations`);
                    }
                    operationDescription = `Creating new ${entityName}`;
                    response = await this.sapClient.createEntity(service.url, entityType.entitySet!, parameters);
                    break;

                case 'update':
                    if (!entityType.updatable) {
                        throw new Error(`Entity '${entityName}' does not support update operations`);
                    }
                    {
                        const updateKeyValue = this.buildKeyValue(entityType, parameters);
                        const updateData = { ...parameters };
                        entityType.keys.forEach(key => delete updateData[key]);
                        operationDescription = `Updating ${entityName} with key: ${updateKeyValue}`;
                        response = await this.sapClient.updateEntity(service.url, entityType.entitySet!, updateKeyValue, updateData);
                    }
                    break;

                case 'delete':
                    if (!entityType.deletable) {
                        throw new Error(`Entity '${entityName}' does not support delete operations`);
                    }
                    {
                        const deleteKeyValue = this.buildKeyValue(entityType, parameters);
                        operationDescription = `Deleting ${entityName} with key: ${deleteKeyValue}`;
                        await this.sapClient.deleteEntity(service.url, entityType.entitySet!, deleteKeyValue);
                        response = { data: { message: `Successfully deleted ${entityName} with key: ${deleteKeyValue}`, success: true } };
                    }
                    break;

                default:
                    throw new Error(`Unsupported operation: ${operation}`);
            }

            let responseText = `SUCCESS: ${operationDescription}\n\n`;
            responseText += `== RESULT ==\n`;
            responseText += JSON.stringify(response.data, null, 2);

            return {
                content: [{
                    type: "text" as const,
                    text: responseText
                }]
            };

        } catch (error) {
            this.logger.error('Error executing entity operation:', error);

            const errorMessage = error instanceof Error ? error.message : String(error);
            const hasSelectString = args.selectString && (args.selectString as string).trim().length > 0;

            // Check if error might be related to $select not being supported
            const selectRelatedErrors = [
                'select',
                '$select',
                'projection',
                'column',
                'field',
                'property not found',
                'invalid property',
                'unknown property'
            ];

            const mightBeSelectError = hasSelectString &&
                selectRelatedErrors.some(term => errorMessage.toLowerCase().includes(term));

            let responseText = `ERROR: Failed to execute ${args.operation} operation on ${args.entityName}\n\n`;
            responseText += `Error Details: ${errorMessage}\n\n`;

            if (mightBeSelectError) {
                responseText += `⚠️ DETECTED: This error might be related to $select not being fully supported by this SAP API.\n\n`;
                responseText += `🔄 RETRY STRATEGY:\n`;
                responseText += `Many SAP OData APIs have incomplete $select support. Please retry the SAME operation with these changes:\n\n`;
                responseText += `1. Remove the selectString parameter (or set it to empty string)\n`;
                responseText += `2. Keep all other parameters the same:\n`;
                responseText += `   - serviceId: "${args.serviceId}"\n`;
                responseText += `   - entityName: "${args.entityName}"\n`;
                responseText += `   - operation: "${args.operation}"\n`;
                if (args.filterString) responseText += `   - filterString: "${args.filterString}"\n`;
                if (args.topNumber) responseText += `   - topNumber: ${args.topNumber}\n`;
                if (args.skipNumber) responseText += `   - skipNumber: ${args.skipNumber}\n`;
                if (args.orderbyString) responseText += `   - orderbyString: "${args.orderbyString}"\n`;
                if (args.expandString) responseText += `   - expandString: "${args.expandString}"\n`;
                responseText += `3. DO NOT include selectString parameter\n\n`;
                responseText += `This will return ALL properties instead of a subset, which works with all SAP APIs.\n`;
            } else if (hasSelectString) {
                responseText += `💡 TIP: If this error persists, try removing the selectString parameter.\n`;
                responseText += `Some SAP OData APIs don't fully support $select. Retry without selectString to get all properties.\n`;
            }

            return {
                content: [{
                    type: "text" as const,
                    text: responseText
                }],
                isError: true
            };
        }
    }

    /**
     * Format a single OData key value correctly based on its EDM type.
     * - Edm.Boolean  → true / false  (no quotes)
     * - Edm.Int*, Edm.Decimal, Edm.Double, etc. → numeric literal  (no quotes)
     * - Everything else (Edm.String, Edm.Guid, Edm.DateTime…) → 'value'  (single-quoted)
     */
    private formatODataKeyValue(edtType: string, value: unknown): string {
        const t = edtType.toLowerCase();
        if (typeof value === 'boolean' || t.includes('boolean')) {
            return String(value);
        }
        if (
            typeof value === 'number' ||
            t.includes('int') ||
            t.includes('decimal') ||
            t.includes('double') ||
            t.includes('single') ||
            t.includes('float') ||
            t.includes('byte')
        ) {
            return String(value);
        }
        return `'${value}'`;
    }

    /**
     * Build a key predicate from caller-supplied keyProperties object.
     * Uses JavaScript type detection (no EDM type metadata needed):
     *   boolean / number → unquoted  |  everything else → single-quoted
     * Returns the predicate without outer parentheses, e.g.:
     *   "K1='10000000',K2='00010',IsActiveEntity=false"
     */
    private buildKeyPredicateFromObject(keyProperties: Record<string, unknown>): string {
        const parts = Object.entries(keyProperties).map(([key, value]) => {
            if (typeof value === 'boolean' || typeof value === 'number') {
                return `${key}=${value}`;
            }
            return `${key}='${value}'`;
        });
        return parts.join(',');
    }

    /**
     * Build key predicate for entity operations (handles single and composite keys).
     * Uses EDM type information from the entity metadata so boolean/numeric keys are
     * formatted without quotes (fixes IsActiveEntity=false for SAP Draft API).
     *
     * Returns the predicate WITHOUT outer parentheses, e.g.:
     *   single string  → "'10000000'"
     *   single boolean → "false"
     *   composite      → "K1='v1',K2=false,K3=123"
     */
    private buildKeyValue(entityType: EntityType, parameters: Record<string, unknown>): string {
        // Resolve key metadata; fall back to Edm.String for any key not found in properties
        const keyMeta = entityType.keys.map(keyName => {
            const prop = entityType.properties.find(p => p.name === keyName);
            return { name: keyName, type: prop?.type || 'Edm.String' };
        });

        if (keyMeta.length === 0) {
            throw new Error(`Entity '${entityType.name}' has no key properties defined`);
        }

        if (keyMeta.length === 1) {
            const { name, type } = keyMeta[0];
            if (!(name in parameters)) {
                throw new Error(`Missing required key property: ${name}. Required keys: ${entityType.keys.join(', ')}`);
            }
            // Single-key shorthand: just the formatted value (no property name prefix)
            return this.formatODataKeyValue(type, parameters[name]);
        }

        // Composite key: explicit property=value pairs
        const keyParts = keyMeta.map(({ name, type }) => {
            if (!(name in parameters)) {
                throw new Error(`Missing required key property: ${name}. Required keys: ${entityType.keys.join(', ')}`);
            }
            return `${name}=${this.formatODataKeyValue(type, parameters[name])}`;
        });
        return keyParts.join(',');
    }

    // ─── New Tool Handlers ────────────────────────────────────────────────────

    /**
     * execute-function-import: call any OData Function Import / Action.
     * Supports bound actions (entityPath provided) and unbound (no entityPath).
     */
    private async executeFunctionImport(args: Record<string, unknown>) {
        try {
            const serviceId = args.serviceId as string;
            const functionName = args.functionName as string;
            const entityPath = args.entityPath as string | undefined;
            const parameters = (args.parameters as Record<string, unknown>) || {};
            const httpMethod = ((args.httpMethod as string) || 'POST').toUpperCase() as 'GET' | 'POST';

            if (!serviceId || !functionName) {
                return {
                    content: [{ type: "text" as const, text: "ERROR: serviceId and functionName are required." }],
                    isError: true
                };
            }

            // Look up service
            const service = this.discoveredServices.find(s => s.id === serviceId);
            if (!service) {
                return {
                    content: [{ type: "text" as const, text: `ERROR: Service not found: ${serviceId}. Use discover-sap-data to find available services.` }],
                    isError: true
                };
            }

            // Permission check — for bound actions, use the entity set from the entityPath.
            // For unbound actions without an entity path, derive entity name from the function
            // name heuristic or allow if no entity can be determined.
            if (entityPath) {
                // Extract entity set name: e.g. "C_Purchasereqitmdtlsext(K='v')" → "C_Purchasereqitmdtlsext"
                const boundEntity = entityPath.split('(')[0];
                // Map HTTP method to a permission operation
                const operation = httpMethod === 'GET' ? 'read' : 'update';
                // TODO: Re-enable once Config App has entries populated
                // const permissionDenied = await this.enforcePermission(serviceId, boundEntity, operation);
                // if (permissionDenied) return permissionDenied;
            }

            // Set user token
            if (this.userToken) {
                this.sapClient.setUserToken(this.userToken);
            }

            // Build the namespace-qualified function name for bound actions.
            // If functionName already contains a dot it is assumed to be fully qualified.
            const namespace = service.metadata?.namespace;
            const qualifiedName = (entityPath && namespace && !functionName.includes('.'))
                ? `${namespace}.${functionName}`
                : functionName;

            // Construct the path relative to the service base URL:
            //   bound:   EntityPath/namespace.FunctionName
            //   unbound: FunctionName
            const functionPath = entityPath
                ? `${entityPath}/${qualifiedName}`
                : qualifiedName;

            this.logger.debug(`Executing function import: ${httpMethod} ${service.url}${functionPath}`);

            const response = await this.sapClient.executeFunctionImport(
                service.url,
                functionPath,
                httpMethod === 'POST' ? parameters : undefined,
                httpMethod,
                httpMethod === 'GET' ? parameters : undefined
            );

            let responseText = `SUCCESS: Executed ${functionName}`;
            if (entityPath) responseText += ` on ${entityPath}`;
            responseText += `\n\n== RESULT ==\n`;
            responseText += JSON.stringify(response.data, null, 2);

            return {
                content: [{ type: "text" as const, text: responseText }]
            };

        } catch (error) {
            this.logger.error('Error executing function import:', error);
            const msg = error instanceof Error ? error.message : String(error);
            return {
                content: [{ type: "text" as const, text: `ERROR: Failed to execute function import '${args.functionName}'\n\nDetails: ${msg}` }],
                isError: true
            };
        }
    }

    /**
     * patch-sap-entity: PATCH an entity using caller-supplied key properties.
     * Handles IsActiveEntity=false for SAP Draft API without relying on entity metadata
     * for key construction — the caller provides the exact key values including virtuals.
     */
    private async patchSapEntity(args: Record<string, unknown>) {
        try {
            const serviceId = args.serviceId as string;
            const entityName = args.entityName as string;
            const keyProperties = args.keyProperties as Record<string, unknown>;
            const updateFields = args.updateFields as Record<string, unknown>;

            if (!serviceId || !entityName || !keyProperties || !updateFields) {
                return {
                    content: [{ type: "text" as const, text: "ERROR: serviceId, entityName, keyProperties and updateFields are all required." }],
                    isError: true
                };
            }

            // Look up service
            const service = this.discoveredServices.find(s => s.id === serviceId);
            if (!service) {
                return {
                    content: [{ type: "text" as const, text: `ERROR: Service not found: ${serviceId}. Use discover-sap-data to find available services.` }],
                    isError: true
                };
            }

            // Resolve entity set name from entity type metadata; fall back to entityName itself
            const entityType = service.metadata?.entityTypes?.find(e => e.name === entityName);
            const entitySet = entityType?.entitySet || entityName;

            // Permission check
            // TODO: Re-enable once Config App has entries populated
            // const permissionDenied = await this.enforcePermission(serviceId, entitySet, 'update');
            // if (permissionDenied) return permissionDenied;

            // Build OData key predicate using JavaScript type detection
            const keyPredicate = this.buildKeyPredicateFromObject(keyProperties);
            const entityPath = `${entitySet}(${keyPredicate})`;

            // Set user token
            if (this.userToken) {
                this.sapClient.setUserToken(this.userToken);
            }

            this.logger.debug(`Patching entity: PATCH ${service.url}${entityPath}`);

            const response = await this.sapClient.patchEntityByPath(service.url, entityPath, updateFields);

            let responseText = `SUCCESS: Patched ${entitySet}(${keyPredicate})\n\n`;
            responseText += `Updated fields: ${Object.keys(updateFields).join(', ')}\n\n`;
            responseText += `== RESULT ==\n`;
            responseText += JSON.stringify(response.data ?? { message: 'Update accepted (no content returned)' }, null, 2);

            return {
                content: [{ type: "text" as const, text: responseText }]
            };

        } catch (error) {
            this.logger.error('Error patching SAP entity:', error);
            const msg = error instanceof Error ? error.message : String(error);
            return {
                content: [{ type: "text" as const, text: `ERROR: Failed to patch entity '${args.entityName}'\n\nDetails: ${msg}` }],
                isError: true
            };
        }
    }

    /**
     * get-service-metadata: return $metadata in one of several formats.
     */
    private async getServiceMetadata(args: Record<string, unknown>) {
        try {
            const serviceId = args.serviceId as string;
            const format = ((args.format as string) || 'summary').toLowerCase();

            if (!serviceId) {
                return {
                    content: [{ type: "text" as const, text: "ERROR: serviceId is required." }],
                    isError: true
                };
            }

            const service = this.discoveredServices.find(s => s.id === serviceId);
            if (!service) {
                return {
                    content: [{ type: "text" as const, text: `ERROR: Service not found: ${serviceId}. Use discover-sap-data to find available services.` }],
                    isError: true
                };
            }

            // ── full-xml ────────────────────────────────────────────────────────
            if (format === 'full-xml') {
                const rawXml = await this.sapClient.fetchRawMetadata(service.metadataUrl);
                return {
                    content: [{ type: "text" as const, text: rawXml }]
                };
            }

            const metadata = service.metadata;
            if (!metadata) {
                return {
                    content: [{ type: "text" as const, text: `WARNING: Metadata not available for service ${serviceId}. The service may not have loaded properly.` }]
                };
            }

            // ── function-imports-only ───────────────────────────────────────────
            if (format === 'function-imports-only') {
                const fis = metadata.functionImports || [];
                let text = `[FUNCTION IMPORTS] ${service.title} (${serviceId})\n`;
                text += `Namespace: ${metadata.namespace}\n`;
                text += `Found ${fis.length} function imports / actions\n\n`;
                text += `USAGE: Call execute-function-import with:\n`;
                text += `  - serviceId: "${serviceId}"\n`;
                text += `  - functionName: (one of the names below)\n`;
                text += `  - entityPath: (for bound actions — include key predicate)\n\n`;
                text += JSON.stringify({ functionImports: fis }, null, 2);
                return {
                    content: [{ type: "text" as const, text }]
                };
            }

            // ── navigation-properties-only ──────────────────────────────────────
            if (format === 'navigation-properties-only') {
                const navProps = metadata.entityTypes.map(et => ({
                    entityType: et.name,
                    entitySet: et.entitySet,
                    navigationProperties: et.navigationProperties
                })).filter(e => e.navigationProperties.length > 0);

                let text = `[NAVIGATION PROPERTIES] ${service.title} (${serviceId})\n`;
                text += `Namespace: ${metadata.namespace}\n\n`;
                text += JSON.stringify({ navigationProperties: navProps }, null, 2);
                return {
                    content: [{ type: "text" as const, text }]
                };
            }

            // ── summary (default) ───────────────────────────────────────────────
            const summary = {
                service: {
                    serviceId: service.id,
                    title: service.title,
                    description: service.description,
                    odataVersion: service.odataVersion,
                    url: service.url
                },
                namespace: metadata.namespace,
                entityTypes: metadata.entityTypes.map(et => ({
                    name: et.name,
                    entitySet: et.entitySet,
                    keys: et.keys,
                    isDraftEnabled: et.keys.includes('IsActiveEntity') ||
                        et.properties.some(p => p.name === 'IsActiveEntity') ||
                        et.navigationProperties.some(n => n.name === 'DraftAdministrativeData'),
                    capabilities: {
                        creatable: et.creatable,
                        updatable: et.updatable,
                        deletable: et.deletable
                    },
                    navigationProperties: et.navigationProperties.map(n => ({
                        name: n.name,
                        type: n.type,
                        multiplicity: n.multiplicity
                    }))
                })),
                functionImports: metadata.functionImports || [],
                stats: {
                    entityTypeCount: metadata.entityTypes.length,
                    functionImportCount: (metadata.functionImports || []).length,
                    draftEnabledEntityCount: metadata.entityTypes.filter(et =>
                        et.keys.includes('IsActiveEntity') ||
                        et.properties.some(p => p.name === 'IsActiveEntity')
                    ).length
                }
            };

            let text = `[SERVICE METADATA SUMMARY] ${service.title} (${serviceId})\n\n`;
            text += `Namespace: ${metadata.namespace}\n`;
            text += `Entity Types: ${summary.stats.entityTypeCount} (${summary.stats.draftEnabledEntityCount} draft-enabled)\n`;
            text += `Function Imports / Actions: ${summary.stats.functionImportCount}\n\n`;
            if (summary.stats.draftEnabledEntityCount > 0) {
                text += `ℹ️  DRAFT-ENABLED SERVICE: Use execute-function-import (EditAction/ActivationAction/DiscardAction) for the edit lifecycle.\n\n`;
            }
            text += JSON.stringify(summary, null, 2);

            return {
                content: [{ type: "text" as const, text }]
            };

        } catch (error) {
            this.logger.error('Error in get-service-metadata:', error);
            const msg = error instanceof Error ? error.message : String(error);
            return {
                content: [{ type: "text" as const, text: `ERROR: Failed to get metadata for service '${args.serviceId}'\n\nDetails: ${msg}` }],
                isError: true
            };
        }
    }

    // ─── End New Tool Handlers ────────────────────────────────────────────────

    /**
     * Register service metadata resources (unchanged from original)
     */
    public registerServiceMetadataResources(): void {
        this.mcpServer.registerResource(
            "sap-service-metadata",
            new ResourceTemplate("sap://service/{serviceId}/metadata", { list: undefined }),
            {
                title: "SAP Service Metadata",
                description: "Metadata information for SAP OData services"
            },
            async (uri, variables) => {
                const serviceId = typeof variables.serviceId === "string" ? variables.serviceId : "";
                const service = this.discoveredServices.find(s => s.id === serviceId);
                if (!service) {
                    throw new Error(`Service not found: ${serviceId}`);
                }
                return {
                    contents: [{
                        uri: uri.href,
                        text: JSON.stringify({
                            service: {
                                id: service.id,
                                title: service.title,
                                description: service.description,
                                url: service.url,
                                version: service.version
                            },
                            entities: service.metadata?.entityTypes?.map(entity => ({
                                name: entity.name,
                                entitySet: entity.entitySet,
                                properties: entity.properties,
                                keys: entity.keys,
                                operations: {
                                    creatable: entity.creatable,
                                    updatable: entity.updatable,
                                    deletable: entity.deletable
                                }
                            })) || []
                        }, null, 2),
                        mimeType: "application/json"
                    }]
                };
            }
        );

        // Register system instructions for Claude AI
        this.mcpServer.registerResource(
            "system-instructions",
            "sap://system/instructions",
            {
                title: "SAP MCP Server Instructions for Claude AI",
                description: "Comprehensive instructions for helping users interact with SAP OData services",
                mimeType: "text/markdown"
            },
            async (uri) => ({
                contents: [{
                    uri: uri.href,
                    text: this.getSystemInstructions(),
                    mimeType: "text/markdown"
                }]
            })
        );

        // Register authentication status resource
        this.mcpServer.registerResource(
            "authentication-status",
            "sap://auth/status",
            {
                title: "Authentication Status and Guidance",
                description: "Current authentication status and user guidance for OAuth flow",
                mimeType: "application/json"
            },
            async (uri) => {
                const authStatus = {
                    authentication: {
                        required: true,
                        configured: true, // XSUAA is configured
                        current_status: this.userToken ? 'authenticated' : 'not_authenticated',
                        token_present: !!this.userToken
                    },
                    user_context: this.userToken ? {
                        has_token: true,
                        message: 'User is authenticated and operations will use their SAP identity',
                        dual_auth_model: {
                            discovery: 'Uses technical user for service metadata discovery',
                            execution: 'Uses your JWT token for all data operations'
                        }
                    } : {
                        has_token: false,
                        message: 'User must authenticate before accessing SAP data',
                        action_required: 'OAuth authentication flow must be completed'
                    },
                    claude_ai_instructions: this.userToken ? {
                        status: 'READY',
                        message: 'User is authenticated. You can now help them access SAP data.',
                        workflow: [
                            'Level 1: Call discover-sap-data to find services/entities (returns minimal data)',
                            'Level 2: Call get-entity-metadata for selected entity (returns full schema)',
                            'Optional: Call get-service-metadata to discover function imports and nav properties',
                            'Level 3: Call execute-sap-operation (CRUD), execute-function-import (actions), or patch-sap-entity (draft updates)'
                        ],
                        architecture: '6-tool progressive discovery: discovery → metadata → execution (CRUD + actions + patches)',
                        security_context: 'Operations execute under authenticated user identity'
                    } : {
                        status: 'AUTHENTICATION_REQUIRED',
                        message: 'CRITICAL: User must authenticate before you can help with SAP operations',
                        required_actions: [
                            'Guide user through OAuth authentication flow',
                            'Explain authentication is mandatory for SAP access',
                            'Provide clear step-by-step authentication instructions',
                            'Do NOT attempt SAP operations without authentication'
                        ],
                        oauth_flow_guidance: {
                            step1: 'Direct user to /oauth/authorize endpoint',
                            step2: 'User logs in with SAP BTP credentials',
                            step3: 'User copies access token from callback',
                            step4: 'User provides token to MCP client',
                            step5: 'Token is included in Authorization header for all requests'
                        }
                    },
                    endpoints: {
                        authorize: '/oauth/authorize',
                        callback: '/oauth/callback',
                        refresh: '/oauth/refresh',
                        userinfo: '/oauth/userinfo',
                        discovery: '/.well-known/oauth-authorization-server'
                    },
                    security_model: {
                        type: 'OAuth 2.0 with SAP XSUAA',
                        token_lifetime: '1 hour',
                        refresh_token_lifetime: '24 hours',
                        scope_based_authorization: true,
                        audit_trail: 'All operations logged under user identity'
                    }
                };

                return {
                    contents: [{
                        uri: uri.href,
                        text: JSON.stringify(authStatus, null, 2),
                        mimeType: "application/json"
                    }]
                };
            }
        );

        this.mcpServer.registerResource(
            "sap-services",
            "sap://services",
            {
                title: "Available SAP Services",
                description: "List of all discovered SAP OData services",
                mimeType: "application/json"
            },
            async (uri) => ({
                contents: [{
                    uri: uri.href,
                    text: JSON.stringify({
                        totalServices: this.discoveredServices.length,
                        categories: Array.from(new Set(Array.from(this.serviceCategories.values()).flat())),
                        services: this.discoveredServices.map(service => ({
                            id: service.id,
                            title: service.title,
                            description: service.description,
                            entityCount: service.metadata?.entityTypes?.length || 0,
                            categories: this.serviceCategories.get(service.id) || []
                        }))
                    }, null, 2)
                }]
            })
        );
    }

    /**
     * Generate comprehensive system instructions for AI assistants
     */
    private getSystemInstructions(): string {
        return `# SAP OData MCP Server - AUTHENTICATION REQUIRED

CRITICAL FOR AI ASSISTANTS: This server requires OAuth 2.0 authentication for all SAP operations.

== AUTHENTICATION STATUS CHECK ==

BEFORE HELPING USERS: Always check the authentication-status resource (sap://auth/status) to understand if the user is authenticated.

== MANDATORY AUTHENTICATION WORKFLOW ==

If user is NOT authenticated:
1. STOP - Do not attempt any SAP operations
2. GUIDE USER - Direct them to complete OAuth authentication first
3. EXPLAIN - Authentication is mandatory for SAP data access
4. PROVIDE INSTRUCTIONS - Step-by-step OAuth flow guidance

Authentication Requirements:
1. User must navigate to /oauth/authorize endpoint to get access token
2. User must include token in Authorization header: \`Bearer <token>\`
3. Server uses dual authentication model:
   - Discovery operations: Technical user (reliable metadata access)
   - Data operations: User's JWT token (proper authorization and audit trail)

== AVAILABLE TOOLS ==

You have access to 6 tools covering the full SAP OData interaction lifecycle:

── DISCOVERY ──────────────────────────────────────────────────────────────────

LEVEL 1: discover-sap-data (LIGHTWEIGHT DISCOVERY)
- Purpose: Search and find relevant services/entities with MINIMAL data
- Returns: Only serviceId, serviceName, entityName, entityCount
- Parameters: query, category (business-partner/sales/finance/procurement/hr/logistics/all), limit

LEVEL 2: get-entity-metadata (FULL ENTITY SCHEMA)
- Purpose: Get complete schema for a specific entity
- Returns: ALL properties, types, keys, nullable, maxLength, capabilities
- Parameters: serviceId, entityName

get-service-metadata (FUNCTION IMPORTS & ADVANCED METADATA)
- Purpose: Discover function imports, nav properties, and draft indicators
- Returns: Summary JSON, raw XML, function imports only, or nav props only
- Parameters: serviceId, format (summary|full-xml|function-imports-only|navigation-properties-only)
- Use this: Before execute-function-import to find out what actions exist

── EXECUTION (all require authentication) ────────────────────────────────────

LEVEL 3: execute-sap-operation (CRUD OPERATIONS)
- Purpose: Perform standard CRUD on entities
- Operations: read, read-single, create, update, patch, delete
- Parameters: serviceId, entityName, operation, parameters, OData filter/select/top/skip options

execute-function-import (SAP ACTIONS & FUNCTION IMPORTS)
- Purpose: Invoke any OData Function Import or Action (not available via CRUD)
- Use for: EditAction, ActivationAction, DiscardAction, AssignSourceOfSupply, CreatePurchaseOrder, etc.
- Parameters: serviceId, functionName, entityPath (optional), parameters, httpMethod (GET|POST)
- Bound actions: supply entityPath with full key predicate
- Unbound actions: omit entityPath

patch-sap-entity (PARTIAL UPDATE WITH COMPOSITE KEYS)
- Purpose: PATCH an entity with explicit key properties (incl. virtual IsActiveEntity)
- Use for: Updating draft entities in SAP Draft API pattern before ActivationAction
- Parameters: serviceId, entityName, keyProperties {IsActiveEntity: false, ...}, updateFields

== SAP DRAFT API LIFECYCLE ==

Many SAP Fiori services (MM_PUR_PR_PROCESS_SRV, SD_ORDER_PROCESS_SRV, etc.) use the Draft API.
Identifiable by IsActiveEntity in entity keys or DraftAdministrativeData nav property.

EDIT WORKFLOW:
1. get-service-metadata (function-imports-only) → confirm EditAction/ActivationAction exist
2. execute-sap-operation (read-single, IsActiveEntity=true) → read current values
3. execute-function-import (EditAction, entityPath with IsActiveEntity=true) → create draft
4. patch-sap-entity (keyProperties with IsActiveEntity=false, updateFields) → update draft
5. execute-function-import (ActivationAction, entityPath with IsActiveEntity=false) → save
   OR execute-function-import (DiscardAction) → discard changes

== RECOMMENDED STANDARD WORKFLOW ==

✅ CORRECT Workflow for CRUD:
1. discover-sap-data → Find relevant services/entities (minimal data)
2. get-entity-metadata → Get full schema for selected entity
3. execute-sap-operation → Execute operation using schema from step 2

✅ CORRECT Workflow for Draft Editing:
1. discover-sap-data → Find service
2. get-service-metadata (function-imports-only) → Confirm action names
3. execute-function-import (EditAction) → Create draft
4. patch-sap-entity → Update draft fields
5. execute-function-import (ActivationAction) → Commit changes

⚠️ IMPORTANT REMINDERS:
- Always check get-service-metadata before execute-function-import to confirm the exact function name
- For draft entities, always pass IsActiveEntity as a native boolean (not string)
- The 'patch' operation in execute-sap-operation is identical to 'update' (both send HTTP PATCH)

== BEST PRACTICES ==

Authentication Guidance:
- Always remind users about OAuth requirements
- If operations fail with auth errors, guide them to get a fresh token
- Explain that discovery uses technical user, operations use their credentials

Query Optimization:
- Use OData query options (filterString, topNumber) to limit data
- Encourage filtering to avoid large result sets
- Show users how to construct proper OData filters
- IMPORTANT: selectString ($select) is NOT fully supported by all SAP OData APIs
  * If operation fails with $select-related error, retry WITHOUT selectString
  * The error handler will detect this and provide automatic retry instructions
  * Some SAP APIs silently ignore $select, others return errors

Error Handling:
- If entity not found, suggest using discovery tools first
- For permission errors, explain JWT token requirements
- Guide users to check entity capabilities before operations
- For $select errors: Automatically instruct to retry without selectString parameter
- Follow retry instructions in error messages - they contain exact parameters to use

Natural Language Processing:
- Translate user requests into appropriate tool calls
- Break complex requests into multiple steps
- Explain what you're doing and why

== COMMON USER SCENARIOS ==

"Show me customer data"
1. discover-sap-data with query: "customer" → Returns minimal list of customer-related entities
2. get-entity-metadata for selected entity → Returns full schema
3. execute-sap-operation to read with filters (use properties from step 2)

"I need to update a customer's email"
1. discover-sap-data with query: "customer" → Find customer entities
2. get-entity-metadata for Customer entity → Get full schema with email property
3. execute-sap-operation with operation: "update" (use schema from step 2)

"Create a new sales order"
1. discover-sap-data with query: "sales order" → Find sales order entities
2. get-entity-metadata for SalesOrder entity → Get full schema and check creatable=true
3. execute-sap-operation with operation: "create" (use required fields from step 2)

"Find all entities in the system"
1. discover-sap-data with no query → Returns ALL services with entity lists (minimal)
2. Browse results and select entity of interest
3. get-entity-metadata for selected entity → Get full details if needed

== IMPORTANT REMINDERS ==

- Always authenticate first: Guide users through OAuth flow
- Respect entity capabilities: Don't attempt creates on read-only entities
- Use proper OData syntax: Help construct valid filters and selects
- Security context: Operations run under user's SAP credentials
- Token expiration: Tokens expire (typically 1 hour) - guide refresh

== YOUR ROLE ==

Act as an expert SAP consultant who:
- Understands business processes and data relationships
- Can translate business needs into technical operations
- Provides clear, step-by-step guidance
- Explains SAP concepts in user-friendly terms
- Ensures secure, authorized access to data

Remember: You're not just executing commands, you're helping users understand and work with their SAP data safely and effectively.`;
    }
}