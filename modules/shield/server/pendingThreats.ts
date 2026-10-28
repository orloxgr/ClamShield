import path from "node:path";

function fileKey(value: string) {
    return /^[a-z]:[\\/]|^\\\\/i.test(value)
        ? path.win32.resolve(value).toLowerCase()
        : path.resolve(value);
}

function fingerprintKey(fingerprint: any) {
    return fingerprint ? `${fingerprint.size}:${fingerprint.mtimeMs}` : "";
}

// Scanner providers describe the same file independently. Keep one decision and
// retain each provider's evidence when the user sends that decision to Results.
export class PendingThreats {
    readonly items: any[] = [];
    private resolved = new Map<string, string>();
    private completed = new Set<string>();

    register(threat: any, fingerprint: any) {
        const key = fileKey(threat.originalPath);
        const version = fingerprintKey(fingerprint);
        if (this.resolved.has(key) && (!version || this.resolved.get(key) === version)) return null;
        const detection = { ...threat, engine: threat.engine || "ClamAV" };
        const existing = this.items.find(item => fileKey(item.originalPath) === key);
        if (existing) {
            if (version) existing.fingerprint = version;
            if (!existing.detections.some((item: any) => item.engine === detection.engine && item.threatName === detection.threatName)) {
                existing.detections.push(detection);
            }
            return existing;
        }
        const item = { ...detection, fingerprint: version, detections: [detection] };
        this.items.push(item);
        return item;
    }

    wasResolved(id: string) { return this.completed.has(id); }

    fileAdded(filePath: string) { this.resolved.delete(fileKey(filePath)); }

    resolve(id: string) {
        const index = this.items.findIndex(item => item.id === id);
        if (index < 0) return;
        const [threat] = this.items.splice(index, 1);
        if (threat.fingerprint) this.resolved.set(fileKey(threat.originalPath), threat.fingerprint);
        this.completed.add(id);
        // Bound memory while allowing late provider reports and retried IPC calls.
        if (this.resolved.size > 1000) this.resolved.delete(this.resolved.keys().next().value!);
        if (this.completed.size > 1000) this.completed.delete(this.completed.values().next().value!);
    }
}
