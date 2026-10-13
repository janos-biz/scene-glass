export { ConfigPathInputError, resolveSceneGlassConfigPath } from './startup/config-path.js';
export type { ConfigPathInput } from './startup/config-path.js';
export { MCP_PROTOCOL_VERSION, createMcpDispatcher } from './mcp/dispatcher.js';
export type {
  JsonRpcFailure,
  JsonRpcId,
  JsonRpcResponse,
  JsonRpcSuccess,
  McpDispatcher,
  McpDispatcherOptions,
  McpErrorData,
  McpScope,
  McpServerInfo,
  McpTool,
  McpToolName,
} from './mcp/dispatcher.js';

export { createAnnotationTools } from './mcp/annotation-tools.js';
export type {
  AnnotationListResult,
  AnnotationMutationResult,
  AnnotationToolDependencies,
  ProjectLock,
} from './mcp/annotation-tools.js';

export { createPromptExportTool } from './mcp/export-tool.js';
export type { PromptExportResult, PromptExportToolDependencies } from './mcp/export-tool.js';

export {
  PlatformStartupError,
  SerialProjectLock,
  createSceneGlassApp,
  createSceneGlassAppForTest,
  preflightSceneGlassStartup,
  registerSceneGlassLoader,
} from './app.js';
export type {
  CreateSceneGlassAppForTestOptions,
  CreateSceneGlassAppOptions,
  PreflightSceneGlassStartupOptions,
  ProjectRootProbe,
  SceneGlassStartupPreflight,
  SceneGlassStartupPreflightProject,
} from './app.js';
