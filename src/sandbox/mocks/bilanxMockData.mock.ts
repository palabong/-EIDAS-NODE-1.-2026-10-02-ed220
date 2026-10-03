/**
 * ============================================================
 * BILANX DK-SVS — MOCK CLIENT-SIDE STRESS TEST LAYER
 * ============================================================
 * 
 * ⚠️  USO STRETTAMENTE LIMITATO:
 * - Solo per stress test frontend (INP, concurrent validation, dataset 5000+)
 * - Solo all’interno della cartella src/sandbox/
 * - NON importare mai nei componenti di produzione
 * - NON sostituire mai la logica dual-key reale di validazione sovrana
 *
 * Qualsiasi violazione di questa regola genera bug in produzione.
 * ============================================================
 */
/**
 * Represents a single mock item for the Bilanx dual-key POS validation terminal.
 */
export interface BilanxMockItem {
  id: string;
  nome: string;
  categoria: string;
  descrizione: string;
  prezzo: number;
  merchantRef: string;
  validationStatus: 'pending' | 'in_progress' | 'dual_key_in_progress' | 'eidas_in_progress' | 'validated' | 'failed';
  lastValidationAttempt: string | null;
  dualKeyRef: string;
  simulatedLatencyMs: number;
  currentPhase?: 'dual_key' | 'eidas';
  eidasDetails?: {
    attributesDisclosed?: string[];
    errorCode?: string;
    errorMessage?: string;
  };
}

const CATEGORIES = [
  'Alimentari',
  'Bevande',
  'Elettronica',
  'Moda e Accessori',
  'Casa e Giardino',
  'Salute e Igiene',
  'Strumenti e Attrezzi',
  'Regolamentati'
];

const ADJECTIVES = [
  'Premium',
  'Bio',
  'Professionale',
  'Standard',
  'Avanzato',
  'Certificato',
  'Classico',
  'Moderno'
];

const NOUNS = [
  'Prodotto',
  'Articolo',
  'Lotto',
  'Dispositivo',
  'Set',
  'Kit',
  'Accessorio',
  'Componente'
];

/**
 * Generates a purely client-side dataset of Bilanx items for stress-testing.
 * 
 * @param count Number of mock items to generate. Default is 5000.
 * @returns Array of BilanxMockItem
 */
export function generateBilanxMockData(count: number = 5000): BilanxMockItem[] {
  // Memory and render implications for a 5000-item dataset in React 19:
  // 1. Generating 5000 items synchronously allocates a continuous memory block quickly
  //    without triggering major GC pauses, maintaining stable V8 performance.
  // 2. Rendering 5000 DOM nodes simultaneously will cause severe layout thrashing.
  //    It is strictly required to use virtualization (e.g., virtual list) combined
  //    with React 19 concurrent features (e.g., useDeferredValue) to avoid blocking the main UI thread.
  const result: BilanxMockItem[] = [];

  for (let i = 0; i < count; i++) {
    const categoryIndex = (i * 31) % CATEGORIES.length;
    const adjectiveIndex = (i * 17) % ADJECTIVES.length;
    const nounIndex = (i * 13) % NOUNS.length;
    
    const categoria = CATEGORIES[categoryIndex];
    const noun = NOUNS[nounIndex];
    const adjective = ADJECTIVES[adjectiveIndex];
    const modelNumber = 1000 + (i * 7 % 9000);
    
    const id = `BILANX-${String(i).padStart(6, '0')}`;
    const nome = `${noun} ${categoria} ${adjective} ${modelNumber}`;
    const descrizione = `Articolo controllato di tipo ${categoria.toLowerCase()} ai fini della validazione dual-key. Da conservare la ricevuta in caso di revisione POS.`;
    
    const pseudoRandomPrice = Math.abs(Math.sin(i * 12.345));
    const prezzo = Number(((pseudoRandomPrice * (899.99 - 4.99)) + 4.99).toFixed(2));
    
    const merchantRef = `MRC-${String((i * 7919 % 900000) + 100000).padStart(6, '0')}`;
    
    const dualKeyRef = `DK-${btoa(String(i) + (i * 137).toString(36)).slice(0, 12).toUpperCase()}`;
    
    const pseudoRandomLatency = Math.abs(Math.cos(i * 45.678));
    const simulatedLatencyMs = Math.floor(pseudoRandomLatency * (1600 - 150 + 1)) + 150;

    result.push({
      id,
      nome,
      categoria,
      descrizione,
      prezzo,
      merchantRef,
      validationStatus: 'pending',
      lastValidationAttempt: null,
      dualKeyRef,
      simulatedLatencyMs
    });
  }

  return result;
}
