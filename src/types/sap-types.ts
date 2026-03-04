// SAP Types
export interface ODataService {
    id: string;
    version: string;
    title: string;
    description: string;
    odataVersion: 'v2' | 'v4';
    url: string;
    metadataUrl: string;
    entitySets: string[];
    metadata: ServiceMetadata | null;
}

export interface ServiceMetadata {
    entityTypes: EntityType[];
    entitySets: Array<{ [key: string]: string | boolean | null }>;
    version: string;
    namespace: string;
    functionImports: FunctionImport[];
}

export interface EntityType {
    name: string;
    entitySet: string | null | undefined;
    namespace: string;
    properties: Property[];
    navigationProperties: NavigationProperty[];
    keys: string[];
    creatable: boolean;
    updatable: boolean;
    deletable: boolean;
    addressable: boolean;
}

export interface Property {
    name: string;
    type: string;
    nullable: boolean;
    maxLength?: string;
}

export interface NavigationProperty {
    name: string;
    type: string;
    multiplicity: '1' | '0..1' | '*';
}

export interface FunctionImport {
    name: string;
    httpMethod: string;
    returnType?: string;
    entitySet?: string;
    isBound?: boolean;
    namespace?: string;
    parameters: FunctionParameter[];
}

export interface FunctionParameter {
    name: string;
    type: string;
    nullable: boolean;
    mode?: string;
}
