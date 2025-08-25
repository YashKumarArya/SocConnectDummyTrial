
// FAISS proxy/local wrapper (stub)
export async function similar(id: string, topK = 5) {
  return [] as Array<{ id: string; score: number }>;
}

export async function reindex() {
  return true;
}
