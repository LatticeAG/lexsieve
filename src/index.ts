// Public API surface for the LexSieve OSS core.
export { jcs, parseJson, type JsonValue } from './jcs.ts';
export {
  sha256Hex, b64uEncode, b64uDecode, ed25519PublicFromSeed, ed25519Sign, ed25519Verify,
} from './crypto.ts';
export { csprngAllocator, isValidId, type IdAllocator, type IdPrefix } from './ids.ts';
export { ClosedError, NotImplementedError, type ErrorCode } from './errors.ts';
export { Engine, SYSTEM_CLOCK, BUDGET, type EngineDeps, type Clock, type Ctx } from './engine.ts';
export { MemorySink, type Sink, type StoredDecision, type ChainHead, type ActiveSnapshotRecord } from './sink.ts';
export { SqliteSink } from './sqlite.ts';
export { StaticLexShield, AxionLexShield, STATIC_POLICY_HASH, type LexShieldPort } from './lexshield.ts';
export { verifyPack, activatePack, configHashOf, CORE_VERSION } from './packs.ts';
export { loadConfig, loadDeployment, checkConfig, resolvePath } from './config.ts';
export { verifyReceipt, verifyReceiptTrust, verifyPack as verifyPackSdk, replay } from './verify.ts';
export { startControlServer } from './control.ts';
export { HostedApiClient } from './hosted.ts';
export { TenantTelemetryStore } from './telemetry.ts';
export {
  nativeExtract, mcpExtract, mcpSerialize, mcpSerializeFailure,
  openaiExtract, openaiSerialize, openaiSerializeFailure,
  checkBlockBounds, decodeWire, receiveWire, failureEnvelopeJson,
  WIRE_CAP, TEXT_CAP, COMPLETION_TIMEOUT_MS, FAILURE_ENVELOPE,
} from './adapters.ts';
export { main as cliMain, VERSION_LINE } from './cli.ts';
export type {
  ScreenRequest, ScreenResponse, Decision, DataEnvelope, SignedReceipt, ReceiptBody,
  SignedPack, PackBody, Config, TrustConfig, TrustKey, Snapshot, Candidate, TextBlock,
  FindingWire, PolicyResponse,
} from './schema.ts';
export type { ModelArtifact } from './model.ts';
export { validateModelArtifact, modelHash, featurize, score } from './model.ts';
