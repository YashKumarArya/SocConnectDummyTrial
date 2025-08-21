import * as vectorClient from '../../libs/vector/client';
import * as simClient from '../../libs/similarity/client';

export const embeddingsRepo = {
  async save(row: { alpha_id: string; alert_id: string; vector: number[]; dimension?: number; embedding_id?: string }) {
    const id = await vectorClient.insertEmbedding({ alpha_id: row.alpha_id, alert_id: row.alert_id, vector: row.vector, dimension: row.dimension || row.vector.length, embedding_id: row.embedding_id });
    // also notify similarity service to add to index
    try {
      await simClient.addEmbedding(row.alpha_id, row.alert_id, row.vector, id);
    } catch (e) {
      // ignore similarity service errors, index can be rebuilt later
      console.warn('similarity.addEmbedding failed', e);
    }
    return id;
  },

  async getSimilarForAlert(alert_id: string) {
    // Try to find the most recent embedding for this alert, then use vector search
    try {
      // simple approach: fetch all embeddings and find one matching alert_id
      const rows = await vectorClient.fetchEmbeddings(1000);
      const found = rows.find((r: any) => r.alert_id === alert_id || r.embedding_id === alert_id);
      if (found && found.vector && found.vector.length) {
        const resp = await simClient.searchByVector(found.vector, 10);
        return resp.results || [];
      }
    } catch (e) {
      console.warn('vector search path failed', e);
    }

    // fallback: search by text (alert_id treated as text)
    try {
      const resp = await simClient.searchByText(alert_id, 5);
      return resp.results || [];
    } catch (e) {
      console.warn('similarity.search failed', e);
      return [];
    }
  }
};
