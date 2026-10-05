import { api, type EntityKind } from './api'

/**
 * Field specs, so Add and Bulk-edit share one dialog instead of four bespoke
 * ones per entity. `bulk: false` marks a field that may only be set at
 * creation — host and port are join keys, and bulk-rewriting them would
 * silently re-point child rows at a different asset.
 */
export type FieldType = 'text' | 'number' | 'bool' | 'tristate' | 'select' | 'multiline'

export interface FieldSpec {
  name: string
  label: string
  type: FieldType
  options?: { value: string | number | boolean | null; label: string }[]
  required?: boolean
  bulk?: boolean
  help?: string
}

const TRISTATE = [
  { value: null, label: 'Not probed' },
  { value: true, label: 'Up' },
  { value: false, label: 'Down' },
]

export const SPECS: Record<EntityKind, FieldSpec[]> = {
  targets: [
    { name: 'kind', label: 'Type', type: 'select', options: [
      { value: 'host', label: 'Host — a machine at an address' },
      { value: 'mobile', label: 'Mobile — an app, no IP of its own' },
      { value: 'cloud', label: 'Cloud — a managed resource' }],
      help: 'A mobile app is named by its bundle or package id, e.g. '
            + 'com.acme.banking.android — it has no address, so IP and Alive '
            + 'are cleared and shown as N/A. A cloud resource is named '
            + 'however its provider names it: a hostname, an ARN, or a '
            + 'resource path.' },
    { name: 'provider', label: 'Cloud provider', type: 'text',
      help: 'aws, azure, gcp, oracle, cloudflare, … Only kept for a cloud '
            + 'target; ignored for the others.' },
    { name: 'host', label: 'Host (FQDN, IP, bundle id, or cloud resource)', type: 'text',
      required: true, bulk: false,
      help: 'Unique within the project. Not a pattern — no wildcards.' },
    { name: 'ip_address', label: 'IP address', type: 'text',
      help: 'Anything that is not an IP literal is stored as empty. '
            + 'Ignored for a mobile target.' },
    { name: 'alive', label: 'Alive', type: 'tristate', options: TRISTATE },
    { name: 'hacked', label: 'Hacked', type: 'bool' },
    { name: 'os', label: 'Operating system', type: 'text' },
    { name: 'tags', label: 'Other names (comma separated)', type: 'text' },
    { name: 'notes', label: 'Notes', type: 'multiline' },
  ],
  services: [
    { name: 'host', label: 'Host', type: 'text', required: true, bulk: false,
      help: 'Must already exist as a target in this project.' },
    { name: 'port', label: 'Port', type: 'number', required: true, bulk: false },
    { name: 'protocol', label: 'Protocol', type: 'select', bulk: false,
      options: [{ value: 'tcp', label: 'tcp' }, { value: 'udp', label: 'udp' }] },
    { name: 'state', label: 'State', type: 'select', options: [
      { value: 'open', label: 'open' }, { value: 'closed', label: 'closed' },
      { value: 'filtered', label: 'filtered' }] },
    { name: 'name', label: 'Service name', type: 'text' },
    { name: 'product', label: 'Product', type: 'text' },
    { name: 'version', label: 'Version', type: 'text' },
    { name: 'banner', label: 'Banner', type: 'multiline' },
  ],
  vulns: [
    { name: 'host', label: 'Host', type: 'text', required: true, bulk: false },
    { name: 'title', label: 'Title', type: 'text', required: true, bulk: false },
    { name: 'severity', label: 'Severity', type: 'select', options: [
      { value: 'critical', label: 'critical' }, { value: 'high', label: 'high' },
      { value: 'medium', label: 'medium' }, { value: 'low', label: 'low' },
      { value: 'info', label: 'info' }] },
    { name: 'status', label: 'Status', type: 'select', options: [
      { value: 'open', label: 'open' }, { value: 'closed', label: 'closed' },
      { value: 're-test', label: 're-test' }] },
    { name: 'port', label: 'Port', type: 'number' },
    { name: 'external_id', label: 'Source ID', type: 'text', bulk: false },
    { name: 'description', label: 'Description', type: 'multiline' },
  ],
  pocs: [
    { name: 'host', label: 'Host', type: 'text', required: true, bulk: false },
    { name: 'title', label: 'Title', type: 'text', required: true, bulk: false },
    { name: 'status', label: 'Status', type: 'select', options: [
      { value: 'confirmed', label: 'confirmed' },
      { value: 'unconfirmed', label: 'unconfirmed' }] },
    { name: 'exit_code', label: 'Exit code', type: 'number',
      help: '0 reproduced · 1 not reproduced · 2 could not test' },
    { name: 'path', label: 'Path', type: 'text' },
    { name: 'notes', label: 'Notes', type: 'multiline' },
  ],
  credentials: [
    { name: 'host', label: 'Host', type: 'text',
      help: 'Free text — a credential often predates the inventory row.' },
    { name: 'username', label: 'Username', type: 'text' },
    { name: 'secret', label: 'Secret', type: 'text', bulk: false,
      help: 'Stored in plaintext. Protect oddjob.db accordingly.' },
    { name: 'kind', label: 'Kind', type: 'select', options: [
      { value: 'password', label: 'password' }, { value: 'hash', label: 'hash' },
      { value: 'key', label: 'key' }, { value: 'token', label: 'token' },
      { value: 'cookie', label: 'cookie' }, { value: 'other', label: 'other' }] },
    { name: 'validated', label: 'Validated', type: 'select', options: [
      { value: 'none', label: 'not tried' }, { value: 'works', label: 'works' },
      { value: 'failed', label: 'failed' }] },
    { name: 'service', label: 'Service', type: 'text' },
    { name: 'port', label: 'Port', type: 'number' },
    { name: 'source', label: 'Source', type: 'text' },
    { name: 'notes', label: 'Notes', type: 'multiline' },
  ],
}

export const LABELS: Record<EntityKind, string> = {
  targets: 'target', services: 'service', vulns: 'vulnerability',
  pocs: 'PoC', credentials: 'credential',
}

export function createFor(kind: EntityKind, project: string, body: Record<string, unknown>) {
  switch (kind) {
    case 'targets': return api.createTarget(project, body)
    case 'services': return api.createService(project, body)
    case 'vulns': return api.createVuln(project, body)
    case 'credentials': return api.createCredential(project, body)
    default: throw new Error(`creating ${kind} from the UI is not wired up`)
  }
}
