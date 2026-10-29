import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { englishText } from "../shared/localization/runtime";

// Legacy focused tests inspect production declarations. Read their new owners,
// not a stale copy of the old monolith; this helper is never part of the server bundle.
export function readBackendSource() {
  const files: string[] = [];
  const visit = (folder: string) => {
    for (const item of fs.readdirSync(folder, { withFileTypes: true })) {
      const file = path.join(folder, item.name);
      if (item.isDirectory()) visit(file);
      else if (file.endsWith(".ts") && !file.endsWith(".test.ts") && !file.endsWith("testSupport.ts")) files.push(file);
    }
  };
  for (const folder of ["server", "modules", "addons", "engines"]) visit(folder);
  return files.sort().map(file => fs.readFileSync(file, "utf8").replace(/^export\s+(?:\/\/[^\n]*\n\s*)?(?=(?:async\s+)?(?:function|class|const|let|var|interface|type|enum)\b)/gm, "")).join("\n");
}

export function serverTestContext(values: Record<string, any>) {
  const context = vm.createContext({ englishText, ...values });
  context.context = context;
  context.runtimeState = context;
  return context;
}
