export type DecimalString = string;

export interface FileIdentity {
  readonly device: DecimalString;
  readonly inode: DecimalString;
}

export interface CredentialAuthority {
  readonly projectId: string;
  readonly path: string;
  readonly device: DecimalString;
  readonly inode: DecimalString;
}

export interface ConfiguredProject {
  readonly projectId: string;
}

export type DescriptorProjectSet =
  readonly ConfiguredProject[] | { readonly projects: readonly ConfiguredProject[] };

export interface StaticHostDescriptorV1 {
  readonly schemaVersion: 1;
  readonly template: 'public/index.html';
  readonly publicRoot: 'public';
  readonly host: '127.0.0.1';
  readonly port: number;
  readonly projectId: string;
  readonly loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js';
  readonly credentialProjectId: string;
  readonly credentialKey: 'SCENE_GLASS_HOST_TOKEN';
  readonly navigation: 'document';
  readonly readinessPath: '/__scene-glass/ready';
  readonly approvedRootIdentity: FileIdentity;
  readonly credentialAuthorities: readonly CredentialAuthority[];
}

export interface VueViteFrameworkVersionTuple {
  readonly framework: 'vue3';
  readonly frameworkVersion: '3.5.40';
  readonly frameworkPluginVersion: '6.0.8';
}

export interface ReactViteFrameworkVersionTuple {
  readonly framework: 'react';
  readonly frameworkVersion: '19.1.1';
  readonly frameworkPluginVersion: '5.0.4';
}

export type ViteFrameworkVersionTuple =
  VueViteFrameworkVersionTuple | ReactViteFrameworkVersionTuple;

export type ViteFramework = ViteFrameworkVersionTuple['framework'];

export interface ViteHostDescriptorBaseV1 {
  readonly schemaVersion: 1;
  readonly viteVersion: '7.3.6';
  readonly projectId: string;
  readonly rootTemplate: 'index.html';
  readonly loaderUrl: 'http://127.0.0.1:4175/scene-glass-loader.js';
  readonly host: '127.0.0.1';
  readonly port: number;
  readonly credentialProjectId: string;
  readonly credentialKey: 'SCENE_GLASS_HOST_TOKEN';
  readonly navigation: 'spa';
  readonly readinessPath: '/__scene-glass/ready';
  readonly approvedRootIdentity: FileIdentity;
  readonly credentialAuthorities: readonly CredentialAuthority[];
  readonly installId: string;
}

export type ViteHostDescriptorV1 = ViteHostDescriptorBaseV1 & ViteFrameworkVersionTuple;
