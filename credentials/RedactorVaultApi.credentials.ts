import type { ICredentialType, INodeProperties } from 'n8n-workflow';

/** Holds the vault passphrase so n8n stores it encrypted, apart from the workflow JSON. */
export class RedactorVaultApi implements ICredentialType {
  name = 'redactorVaultApi';

  displayName = 'Redactor Vault API';

  icon = { light: 'file:redactorVault.svg', dark: 'file:redactorVault.dark.svg' } as const;

  documentationUrl = 'https://github.com/mjmirza/n8n-nodes-redactor#vault-encryption';

  properties: INodeProperties[] = [
    {
      displayName: 'Vault Passphrase',
      name: 'passphrase',
      type: 'string',
      typeOptions: { password: true },
      default: '',
      required: true,
      description:
        'Encrypts stored sessions with AES-256-GCM. Use at least 12 characters, and a different passphrase for each tenant. Sessions written with this passphrase cannot be read without it.',
    },
  ];
}
