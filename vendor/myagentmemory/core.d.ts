/**
 * Shared core logic for agent-memory.
 *
 * Core logic for agent-memory CLI and skills.
 * Zero pi peer dependencies — only node:fs, node:path, node:child_process.
 */
import type { ChildProcess } from "node:child_process";
import { execFile, spawn } from "node:child_process";
/** Override base directory (for testing or platform-specific defaults). */
export declare function _setBaseDir(baseDir: string): void;
/** Reset to default paths. */
export declare function _resetBaseDir(): void;
/** Get the current memory directory path. */
export declare function getMemoryDir(): string;
/** Get the current MEMORY.md path. */
export declare function getMemoryFile(): string;
/** Get the current SCRATCHPAD.md path. */
export declare function getScratchpadFile(): string;
/** Get the current daily log directory path. */
export declare function getDailyDir(): string;
/** Get the current topics directory path. */
export declare function getTopicsDir(): string;
export declare function ensureDirs(): void;
export declare function todayStr(): string;
export declare function yesterdayStr(): string;
export declare function nowTimestamp(): string;
export declare function shortSessionId(sessionId: string): string;
export declare function readFileSafe(filePath: string): string | null;
export declare function dailyPath(date: string): string;
export declare function topicPath(slug: string): string;
export declare function slugifyTopic(name: string): string;
export declare const RESPONSE_PREVIEW_MAX_CHARS = 4000;
export declare const RESPONSE_PREVIEW_MAX_LINES = 120;
export type TruncateMode = "start" | "end" | "middle";
export interface PreviewResult {
    preview: string;
    truncated: boolean;
    totalLines: number;
    totalChars: number;
    previewLines: number;
    previewChars: number;
}
/** Redact common credential shapes before content reaches disk or agent context. */
export declare function redactSecrets(content: string): {
    content: string;
    redacted: boolean;
};
/** Apply trust, lifecycle, and secret policy to complete logical write entries. */
export declare function filterMemoryForContext(content: string, now?: Date): string;
export declare function truncateLines(lines: string[], maxLines: number, mode: TruncateMode): {
    lines: string[];
    truncated: boolean;
};
export declare function truncateText(text: string, maxChars: number, mode: TruncateMode): {
    text: string;
    truncated: boolean;
};
export declare function buildPreview(content: string, options: {
    maxLines: number;
    maxChars: number;
    mode: TruncateMode;
}): PreviewResult;
export declare function formatPreviewBlock(label: string, content: string, mode: TruncateMode): string;
export declare function formatContextSection(label: string, content: string, mode: TruncateMode, maxLines: number, maxChars: number): string;
export interface ScratchpadItem {
    done: boolean;
    text: string;
    meta: string;
}
export declare function parseScratchpad(content: string): ScratchpadItem[];
export declare function serializeScratchpad(items: ScratchpadItem[]): string;
export declare function buildMemoryContext(searchResults?: string): string;
type ExecFileFn = typeof execFile;
type SpawnFn = typeof spawn;
/** Override execFile implementation (for testing). */
export declare function _setExecFileForTest(fn: ExecFileFn): void;
/** Reset execFile implementation (for testing). */
export declare function _resetExecFileForTest(): void;
/** Override skills root directory (for testing). */
export declare function _setSkillsRootForTest(dir: string | null): void;
/** Override home directory (for testing). */
export declare function _setHomeDirForTest(dir: string | null): void;
/** Override spawn implementation (for testing). */
export declare function _setSpawnForTest(fn: SpawnFn): void;
/** Reset spawn implementation (for testing). */
export declare function _resetSpawnForTest(): void;
/** Set qmd availability flag (for testing). */
export declare function _setQmdAvailable(value: boolean): void;
/** Get current qmd availability flag. */
export declare function _getQmdAvailable(): boolean;
/** Get current update timer (for testing). */
export declare function _getUpdateTimer(): ReturnType<typeof setTimeout> | null;
/** Clear the update timer (for testing). */
export declare function _clearUpdateTimer(): void;
/** Get current embed timer (for testing). */
export declare function _getEmbedTimer(): ReturnType<typeof setTimeout> | null;
/** Clear the embed timer (for testing). */
export declare function _clearEmbedTimer(): void;
/** Get the current QMD collection name. */
export declare function getCollectionName(): string;
/** Set the QMD collection name (for platform-specific overrides). */
export declare function setCollectionName(name: string): void;
export declare function qmdInstallInstructions(): string;
export declare function qmdCollectionInstructions(): string;
/** Auto-create the qmd collection and path contexts. */
export declare function setupQmdCollection(): Promise<boolean>;
export declare function detectQmd(): Promise<boolean>;
export declare function checkCollection(name?: string): Promise<boolean>;
export declare function getQmdUpdateMode(): "background" | "manual" | "off";
export declare function ensureQmdAvailableForUpdate(): Promise<boolean>;
export declare function getQmdEmbedMode(): "background" | "manual" | "off";
export declare function runQmdEmbedDetached(): ChildProcess | null;
export declare function scheduleQmdEmbed(): void;
export declare function scheduleQmdUpdate(): void;
export declare function runQmdUpdateNow(): Promise<void>;
export declare function runQmdEmbedNow(): Promise<boolean>;
export declare function ensureQmdAvailableForSync(): Promise<boolean>;
export declare function runQmdSync(): Promise<{
    updateOk: boolean;
    embedOk: boolean;
}>;
export interface InstallSkillsReport {
    ok: boolean;
    projectDir?: string;
    homeDir?: string;
    checked: Array<{
        label: string;
        status: "detected" | "skipped";
        reason?: string;
    }>;
    detected: Array<{
        label: string;
        homeMarker: string;
    }>;
    installed: Array<{
        label: string;
        path: string;
    }>;
    skipped: Array<{
        label: string;
        reason: string;
    }>;
    error?: string;
}
export declare function installSkills(): InstallSkillsReport;
export interface UninstallSkillsReport {
    ok: boolean;
    homeDir?: string;
    removed: Array<{
        label: string;
        path: string;
    }>;
    skipped: Array<{
        label: string;
        reason: string;
    }>;
    error?: string;
}
export declare function uninstallSkills(): UninstallSkillsReport;
export interface QmdHealthInfo {
    totalFiles: number | null;
    vectorsEmbedded: number | null;
    pendingEmbed: number | null;
    lastUpdated: string | null;
    collectionFiles: number | null;
    collectionUpdated: string | null;
    embedMode: string;
}
export declare function parseQmdStatus(stdout: string, collectionName: string): QmdHealthInfo;
export declare function getQmdHealth(): Promise<QmdHealthInfo | null>;
/** Search for memories relevant to the user's prompt. Returns formatted markdown or empty string on error. */
export declare function searchRelevantMemories(prompt: string): Promise<string>;
export interface QmdSearchResult {
    path?: string;
    file?: string;
    context?: string;
    score?: number;
    content?: string;
    chunk?: string;
    snippet?: string;
    title?: string;
    [key: string]: unknown;
}
export declare function getQmdResultPath(r: QmdSearchResult): string | undefined;
export declare function getQmdResultText(r: QmdSearchResult): string;
export declare function runQmdSearch(mode: "keyword" | "semantic" | "deep", query: string, limit: number, options?: {
    signal?: AbortSignal;
}): Promise<{
    results: QmdSearchResult[];
    stderr: string;
}>;
/**
 * Best-effort check of whether vector embeddings are actually usable for
 * semantic/deep search right now. Runs a tiny semantic probe and looks for
 * qmd's "need embeddings" warning. Bounded by a short timeout because the very
 * first semantic query can trigger a model download — returns "unknown" rather
 * than blocking on it. "ready" means the probe ran without the warning; it does
 * not prove the index has content.
 */
export declare function probeEmbeddings(): Promise<"ready" | "missing" | "unknown">;
export interface ToolResult {
    text: string;
    details: Record<string, unknown>;
    isError?: boolean;
}
export declare function memoryWrite(params: {
    target?: "long_term" | "daily" | "topic";
    content: string;
    mode?: "append" | "overwrite";
    sessionId?: string;
    topic?: string;
    date?: string;
    sourceUri?: string;
}): Promise<ToolResult>;
export declare function scratchpadAction(params: {
    action: "add" | "done" | "undo" | "clear_done" | "list";
    text?: string;
    sessionId?: string;
}): Promise<ToolResult>;
export declare function memoryRead(params: {
    target: "long_term" | "scratchpad" | "daily" | "list" | "topic" | "topics";
    date?: string;
    topic?: string;
}): Promise<ToolResult>;
export declare function memorySearch(params: {
    query: string;
    mode?: "keyword" | "semantic" | "deep";
    limit?: number;
}): Promise<ToolResult>;
/** Extract #tag patterns, deduplicated and lowercased. */
export declare function extractTags(content: string): string[];
/** Extract [[link]] patterns. */
export declare function extractLinks(content: string): string[];
/** Extract file-path-like patterns (e.g. src/foo.ts), filtering out URLs. */
export declare function extractFilePaths(content: string): string[];
/** Extract backtick-quoted commands. */
export declare function extractCommands(content: string): string[];
export interface DailyEntry {
    date: string;
    timestamp: string;
    sessionId: string;
    content: string;
    tags: string[];
    links: string[];
    filePaths: string[];
    commands: string[];
}
/** Split a daily file on <!-- timestamp --> markers into individual entries. */
export declare function parseDailyEntries(date: string, content: string): DailyEntry[];
export interface TopicEntry {
    topic: string;
    slug: string;
    date: string;
    timestamp: string;
    sessionId: string;
    content: string;
    tags: string[];
    links: string[];
    filePaths: string[];
    commands: string[];
}
/** Split a topic file on <!-- timestamp --> markers into entries. */
export declare function parseTopicEntries(topic: string, slug: string, content: string): TopicEntry[];
export interface DistilResult {
    ok: boolean;
    dryRun: boolean;
    totalDailyFiles: number;
    totalTopicFiles: number;
    totalEntries: number;
    totalTopicEntries: number;
    totalTags: number;
    tagCounts: Record<string, number>;
    output: string;
}
export declare function distilMemories(params?: {
    dryRun?: boolean;
    sessionId?: string;
}): Promise<DistilResult>;
export {};
