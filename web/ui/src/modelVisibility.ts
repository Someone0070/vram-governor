// Runtime-observed residency is separate from lifecycle support. A fixed
// llama-server can have a loaded model even when the LB cannot unload it.
export function observedResidentModels<T extends {resident_models?:string[]}>(targets:T[]):{target:T;model:string}[]{
  return targets.flatMap(target=>[...new Set(target.resident_models||[])].map(model=>({target,model})));
}
