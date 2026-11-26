// Exact identities mirrored from LOT06 canonical method bridge; no classification authority.
export const protocolMethods: Record<string,string> = {
  "M_SNA_DEG_V1": "STEINER_SNA_DEG_V1",
  "M_SNB_DEG_V1": "STEINER_SNB_DEG_V1",
  "M_ANB_DEG_V1": "STEINER_ANB_DEG_V1",
  "M_U1_NA_DEG_V1": "STEINER_U1_NA_DEG_V1",
  "M_U1_NA_MM_V1": "STEINER_U1_NA_CANONICAL_MM_V2",
  "M_L1_NB_DEG_V1": "STEINER_L1_NB_DEG_V1",
  "M_L1_NB_MM_V1": "STEINER_L1_NB_CANONICAL_MM_V2",
  "M_INTERINCISAL_DEG_V1": "CRANIOM_INTERINCISAL_DEG_V1",
  "M_OCCLUSAL_PLANE_SN_DEG_V1": "STEINER_OCCLUSAL_SN_CANONICAL_DEG_V2",
  "M_SN_GOGN_DEG_V1": "STEINER_SN_GOGN_CANONICAL_DEG_V2",
  "M_L1_GOGN_DEG_V1": "STEINER_L1_GOGN_CANONICAL_DEG_V2",
  "M_SND_DEG_V1": "STEINER_SND_CANONICAL_DEG_V2",
  "M_POG_NB_MM_V1": "STEINER_POG_NB_CANONICAL_MM_V2",
  "M_L1_DLINE_MM_V1": "STEINER_L1_DLINE_CANONICAL_MM_V2",
  "M_L1_DLINE_DEG_V1": "STEINER_L1_DLINE_CANONICAL_DEG_V2",
  "M_FH_GOME_DEG_V1": "TWEED_FMA_CANONICAL_DEG_V2",
  "M_IMPA_GOME_DEG_V1": "TWEED_IMPA_DEG_V1",
  "M_FMIA_L1_FH_DEG_V1": "TWEED_FMIA_CANONICAL_DEG_V2",
  "M_MERRIFIELD_Z_FH_DEG_V1": "MERRIFIELD_Z_CANONICAL_DEG_V2"
};
export const protocolRowsValid = (rows: any[], ids: readonly string[]) =>
  rows.length === ids.length && rows.every((row, index) => {
    const id = ids[index];
    if (!row || row.canonical_measurement_id !== id || row.classification_authority !== false) return false;
    if (row.availability_status !== 'AVAILABLE') return row.availability_status === 'NOT_COMPUTABLE' &&
      row.value === null && Array.isArray(row.measurement_refs) && row.measurement_refs.length === 0 &&
      row.value_authority_method_id == null;
    const refs = row.measurement_refs;
    return typeof row.value === 'number' && Number.isFinite(row.value) &&
      row.unit === (id.includes('_MM_') ? 'mm' : 'deg') &&
      row.value_authority_method_id === protocolMethods[id] &&
      Array.isArray(refs) && refs.length > 0 &&
      refs.every((ref: unknown) => typeof ref === 'string' && ref.trim().length > 0) &&
      new Set(refs).size === refs.length;
  });
export const steinerIds = ["M_SNA_DEG_V1","M_SNB_DEG_V1","M_ANB_DEG_V1","M_U1_NA_DEG_V1","M_U1_NA_MM_V1","M_L1_NB_DEG_V1","M_L1_NB_MM_V1","M_INTERINCISAL_DEG_V1","M_OCCLUSAL_PLANE_SN_DEG_V1","M_SN_GOGN_DEG_V1","M_L1_GOGN_DEG_V1","M_SND_DEG_V1","M_POG_NB_MM_V1","M_L1_DLINE_MM_V1","M_L1_DLINE_DEG_V1"] as const;
export const tweedIds = ["M_FH_GOME_DEG_V1","M_IMPA_GOME_DEG_V1","M_FMIA_L1_FH_DEG_V1","M_MERRIFIELD_Z_FH_DEG_V1"] as const;
