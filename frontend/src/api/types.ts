export type Role = "team_lead" | "operator" | "recon" | "reporter" | string;

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  role: Role;
}

export interface UserProfile {
  username: string;
  role: Role;
}

export interface Campaign {
  id: string;
  name: string;
  client?: string;
  operator?: string;
  targets?: string[];
  scope_cidrs?: string[];
  scope_json?: string;
  noise_profile?: string;
  status?: string;
  created_at?: string;
  [key: string]: unknown;
}

export interface Finding {
  id?: string;
  title?: string;
  severity?: string;
  module_id?: string;
  host?: string;
  mitre_technique?: string;
  confidence?: number;
  [key: string]: unknown;
}

export interface ParamField {
  type: string;
  description: string;
  required: boolean;
  secret: boolean;
  default?: unknown;
  items?: {
    type?: string;
  };
  min?: number;
  max?: number;
  min_len?: number;
  max_len?: number;
  pattern?: string;
}

export type ParamSchema = Record<string, ParamField>;

export interface ModuleMeta {
  id: string;
  name?: string;
  category?: string;
  description?: string;
  opsec_level?: string;
  mitre?: string;
  mitre_list?: string[];
  required_params?: string[];
  optional_params?: string[];
  defaults?: Record<string, unknown>;
  capability_flags?: string[];
  dry_run_supported?: boolean;
  supported_modes?: string[];
  dependency_notes?: string[];
  outcome_semantics?: string[];
  safe_error_categories?: string[];
  param_schema: ParamSchema;
  [key: string]: unknown;
}

export interface ReportItem {
  filename: string;
  format: string;
  size_bytes: number;
  modified_at: number;
}

export interface TemplateMeta {
  name?: string;
  description?: string;
  stages?: number;
  modules?: number;
  [key: string]: unknown;
}

export interface ApiKeyMeta {
  id: string;
  name?: string;
  prefix?: string;
  key_prefix?: string;
  scopes?: string;
  created_at?: string;
  expires_at?: string;
  [key: string]: unknown;
}

export interface ApiKeyCreateResponse extends ApiKeyMeta {
  key: string;
  note?: string;
}
