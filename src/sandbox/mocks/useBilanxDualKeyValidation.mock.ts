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
 * USAGE EXAMPLE (React 19)
 * 
 * import { useFormStatus } from 'react-dom';
 * import { useBilanxDualKeyValidation } from './useBilanxDualKeyValidation';
 * 
 * function StressTestSubmitButton() {
 *   // MUST natively use useFormStatus for pending UI within a form action
 *   const { pending } = useFormStatus();
 *   return (
 *     <button type="submit" disabled={pending} className="btn-stress-test">
 *       {pending ? 'Batch Validation in Progress...' : 'Run Batch Stress Test'}
 *     </button>
 *   );
 * }
 * 
 * export function BilanxValidatorComponent() {
 *   const { items, stats, runStressTest, validateItem, resetDataset } = useBilanxDualKeyValidation();
 *   
 *   return (
 *     <div className="bilanx-sandbox">
 *       <header>
 *         <h1>Dual-Key Sovereign Validation Status</h1>
 *         <p>Stats: {stats.validated} validated, {stats.failed} failed. Avg Latency: {stats.avgLatency}ms</p>
 *       </header>
 *       <form action={runStressTest} className="stress-test-form">
 *         <input type="number" name="count" defaultValue={50} min={1} max={5000} />
 *         <StressTestSubmitButton />
 *         <button type="button" onClick={resetDataset}>Reset Sandbox</button>
 *       </form>
 *       <ul className="virtualized-list">
 *         {items.slice(0, 100).map(item => (
 *           <li key={item.id} onClick={() => validateItem(item.id)}>
 *             [{item.validationStatus}] {item.nome} - {item.dualKeyRef}
 *           </li>
 *         ))}
 *       </ul>
 *     </div>
 *   );
 * }
 */

import { useState, useTransition, useActionState, useMemo, useCallback, useRef } from 'react';
import { BilanxMockItem, generateBilanxMockData } from './bilanxMockData.mock';
import type { HandshakeState, DualKeyValidationResult } from '../hooks/useBilanxDualKeyValidation.real';

async function simulateDualKeyHandshake(item: BilanxMockItem): Promise<{success: boolean, latency: number, error?: string}> {
  const latency = item.simulatedLatencyMs;
  const phase1 = Math.floor(latency * 0.4);
  const phase2 = latency - phase1;

  // Phase 1: Key Agreement
  await new Promise(resolve => setTimeout(resolve, phase1));
  
  // Phase 2: Sovereign Validation
  await new Promise(resolve => setTimeout(resolve, phase2));

  // ~8% failure rate
  const success = Math.random() >= 0.08;
  return {
    success,
    latency,
    error: success ? undefined : 'Sovereign dual-key validation rejected.'
  };
}

export type EidasErrorCode = 'INSUFFICIENT_LOA' | 'IDENTITY_EXPIRED' | 'ATTRIBUTE_MISMATCH' | 'NETWORK_TIMEOUT';

export interface EidasSimulationResult {
  success: boolean;
  latency: number;
  error?: string;
  errorCode?: EidasErrorCode;
  attributesDisclosed?: string[];
  logs: string[];
}

// ⚠️ SIMULATION ONLY: Fake eIDAS validation step for frontend INP stress testing.
async function simulateEidasValidation(item: BilanxMockItem): Promise<EidasSimulationResult> {
  // Random latency between 300ms and 1200ms
  const latency = Math.floor(Math.random() * (1200 - 300 + 1)) + 300;
  await new Promise(resolve => setTimeout(resolve, latency));

  const isAgeRestricted = item.categoria === 'Regolamentati' || item.categoria === 'Bevande';
  const logs: string[] = ['eIDAS: Initiating 3.1.0 minimal disclosure request...'];

  // ~8% failure rate
  const isFailure = Math.random() < 0.08;
  
  if (isFailure) {
    const errorCodes: EidasErrorCode[] = ['INSUFFICIENT_LOA', 'IDENTITY_EXPIRED', 'ATTRIBUTE_MISMATCH', 'NETWORK_TIMEOUT'];
    const errorCode = errorCodes[Math.floor(Math.random() * errorCodes.length)];
    const errorMessages: Record<EidasErrorCode, string> = {
      INSUFFICIENT_LOA: 'eIDAS Wallet Assurance Level (LoA) is insufficient for this transaction.',
      IDENTITY_EXPIRED: 'eIDAS Digital Identity credentials have expired.',
      ATTRIBUTE_MISMATCH: 'User attribute verification failed (e.g., age restriction not met).',
      NETWORK_TIMEOUT: 'Timeout communicating with the eIDAS Gateway.'
    };
    logs.push(`eIDAS: Validation FAILED. Reason: ${errorMessages[errorCode]}`);
    return {
      success: false,
      latency,
      errorCode,
      error: errorMessages[errorCode],
      logs
    };
  }

  // Success case
  const attributesDisclosed = ['Anonymous_DID'];
  if (isAgeRestricted) {
    attributesDisclosed.push('ageOver18=true');
    logs.push('eIDAS: Requesting restricted attributes: ageOver18');
  } else {
    attributesDisclosed.push('posSessionId');
  }
  logs.push(`eIDAS: Validation SUCCESSFUL. Attributes disclosed: ${attributesDisclosed.join(', ')}`);

  return {
    success: true,
    latency,
    attributesDisclosed,
    logs
  };
}

export function useBilanxDualKeyValidation(): {
  // --- Single Item Handshake Interface ---
  state: HandshakeState;
  result: DualKeyValidationResult | null;
  runDualKeyHandshake: (params: { institutionId: string; secondFactorId: string }) => Promise<void>;
  reset: () => void;
  // --- Batch Stress Test Interface ---
  items: BilanxMockItem[];
  pendingIds: Set<string>;
  validateItem: (itemId: string) => void;
  runStressTest: (payload?: number | FormData) => void;
  resetDataset: () => void;
  stats: { total: number; pending: number; validated: number; failed: number; avgLatency: number };
} {
  // --- Single Item Handshake State ---
  const [singleState, setSingleState] = useState<HandshakeState>('IDLE');
  const [singleResult, setSingleResult] = useState<DualKeyValidationResult | null>(null);

  // --- Batch Stress Test State ---
  const [items, setItems] = useState<BilanxMockItem[]>(() => generateBilanxMockData(5000));
  const [pendingIds, setPendingIds] = useState<Set<string>>(new Set());
  const [, startTransition] = useTransition();

  // INP CRITICAL: Use a synchronous ref to track pending IDs to prevent race conditions 
  // on concurrent batch validations, without waiting for the next React render cycle.
  const syncPendingIdsRef = useRef<Set<string>>(new Set());
  
  // Track latest items safely without breaking useCallback reference stability.
  const itemsRef = useRef(items);
  if (itemsRef.current !== items) {
    itemsRef.current = items;
  }

  const validateItem = useCallback((itemId: string) => {
    const execute = async () => {
      if (syncPendingIdsRef.current.has(itemId)) return;
      
      const item = itemsRef.current.find(i => i.id === itemId);
      if (!item) return;

      syncPendingIdsRef.current.add(itemId);

      // INP CRITICAL: We wrap the synchronous state update in a transition. This tells React 
      // that updating the UI to show 'eidas_in_progress' is lower priority than user interaction.
      // Validation now starts with eIDAS simulation, followed by Dual-Key Sovereign Validation.
      startTransition(() => {
        setPendingIds(prev => {
          const next = new Set(prev);
          next.add(itemId);
          return next;
        });
        setItems(prev => prev.map(i => i.id === itemId ? {
          ...i,
          validationStatus: 'eidas_in_progress',
          currentPhase: 'eidas',
          lastValidationAttempt: new Date().toISOString()
        } : i));
      });

      const eidasResult = await simulateEidasValidation(item);

      if (!eidasResult.success) {
        syncPendingIdsRef.current.delete(itemId);
        startTransition(() => {
          setItems(prev => prev.map(i => i.id === itemId ? {
            ...i,
            validationStatus: 'failed',
            currentPhase: 'eidas',
            lastValidationAttempt: new Date().toISOString(),
            eidasDetails: {
              errorCode: eidasResult.errorCode,
              errorMessage: eidasResult.error,
              attributesDisclosed: []
            }
          } : i));
          setPendingIds(prev => {
            const next = new Set(prev);
            next.delete(itemId);
            return next;
          });
        });
        return; // CRITICAL: Abort dual-key phase if eIDAS fails
      }

      // eIDAS successful, move to Dual-Key phase
      startTransition(() => {
        setItems(prev => prev.map(i => i.id === itemId ? {
          ...i,
          validationStatus: 'dual_key_in_progress',
          currentPhase: 'dual_key',
          lastValidationAttempt: new Date().toISOString(),
          eidasDetails: {
            attributesDisclosed: eidasResult.attributesDisclosed
          }
        } : i));
      });

      const dualKeyResult = await simulateDualKeyHandshake(item);

      syncPendingIdsRef.current.delete(itemId);

      // INP CRITICAL: useTransition wraps the post-handshake state update so that rapid successive clicks 
      // on the 5000-item list never block the main thread. React prioritizes user input over the re-render of updated rows.
      startTransition(() => {
        setItems(prev => prev.map(i => i.id === itemId ? {
          ...i,
          validationStatus: dualKeyResult.success ? 'validated' : 'failed',
          currentPhase: 'dual_key',
          lastValidationAttempt: new Date().toISOString()
        } : i));
        setPendingIds(prev => {
          const next = new Set(prev);
          next.delete(itemId);
          return next;
        });
      });
    };

    execute().catch(console.error);
  }, []);

  const [, runStressTestAction] = useActionState(
    async (_state: null, payload: number | FormData | undefined) => {
      let count = 10;
      if (typeof FormData !== 'undefined' && payload instanceof FormData) {
        count = Number(payload.get('count')) || 10;
      } else if (typeof payload === 'number') {
        count = payload;
      }

      // Filter locally to avoid triggering already-pending items in rapid successions
      const pendingItems = itemsRef.current.filter(
        i => i.validationStatus === 'pending' && !syncPendingIdsRef.current.has(i.id)
      );
      
      const selected = pendingItems.sort(() => 0.5 - Math.random()).slice(0, count);

      // INP CRITICAL: We execute batch promises concurrently rather than blocking the thread.
      // `validateItem` is responsible for yielding its own internal state updates to the scheduler.
      await Promise.all(selected.map(item => validateItem(item.id)));
      
      return null;
    },
    null
  );

  const runStressTest = useCallback((payload?: number | FormData) => {
    runStressTestAction(payload);
  }, [runStressTestAction]);

  const resetDataset = useCallback(() => {
    // INP CRITICAL: Large state resets involving 5000 elements must be wrapped in a transition
    // to avoid layout thrashing that blocks the next frame.
    startTransition(() => {
      setItems(generateBilanxMockData(5000));
      setPendingIds(new Set());
      syncPendingIdsRef.current.clear();
    });
  }, []);

  // --- Single Item Handshake Logic ---
  const runDualKeyHandshake = useCallback(async (params: { institutionId: string; secondFactorId: string }) => {
    const { institutionId, secondFactorId } = params;
    setSingleState('INITIATING');
    setSingleResult(null);
    
    const startTime = performance.now();
    const logs: string[] = [];
    
    try {
      // --- 1. eIDAS Phase ---
      logs.push('eIDAS: Initiating 3.1.0 minimal disclosure request...');
      await new Promise(resolve => setTimeout(resolve, 200));

      const eidasSuccess = Math.random() >= 0.05;
      if (!eidasSuccess) {
        logs.push('eIDAS: Validation FAILED. Wallet Assurance Level insufficient.');
        setSingleState('FAILED');
        setSingleResult({
          success: false,
          state: 'FAILED',
          latencyMs: Math.round(performance.now() - startTime),
          institutionalSignatureValid: false,
          userSignatureValid: false,
          bindingValid: false,
          error: 'eIDAS Validation Failed. Aborting Dual-Key Handshake.',
          logs
        });
        return; // CRITICAL: Abort dual-key phase if eIDAS fails
      }

      logs.push('eIDAS: Validation SUCCESSFUL. Attributes disclosed: Anonymous_DID');

      // --- 2. Dual-Key Phase ---
      logs.push('Mock: Generating ECDSA P-256 key pairs for Institution and User...');
      await new Promise(resolve => setTimeout(resolve, 50));
      
      setSingleState('AWAITING_CHALLENGE');
      logs.push('Mock Institution: Generating cryptographic challenge...');
      logs.push('Mock Institution: Signing the challenge...');
      await new Promise(resolve => setTimeout(resolve, 50));
      
      setSingleState('VERIFYING_SIGNATURES');
      logs.push('Mock User: Received challenge. Preparing bound payload...');
      logs.push('Mock User: Signing the strongly bound payload...');
      await new Promise(resolve => setTimeout(resolve, 100));
      
      logs.push('Mock Verifier: Checking Institutional signature...');
      logs.push('Mock Verifier: Reconstructing bound payload and checking User signature...');
      await new Promise(resolve => setTimeout(resolve, 50));
      
      // Simulate high success rate
      const isSuccess = Math.random() >= 0.05;
      
      if (isSuccess) {
        logs.push('Mock Verifier: Cryptographic binding SUCCESSFUL.');
      } else {
        logs.push('Mock Verifier: Cryptographic binding FAILED.');
      }
      
      const endTime = performance.now();
      
      setSingleState(isSuccess ? 'COMPLETED' : 'FAILED');
      setSingleResult({
        success: isSuccess,
        state: isSuccess ? 'COMPLETED' : 'FAILED',
        latencyMs: Math.round(endTime - startTime),
        institutionalSignatureValid: isSuccess,
        userSignatureValid: isSuccess,
        bindingValid: isSuccess,
        error: isSuccess ? undefined : 'Simulated mock cryptographic failure',
        logs
      });
      
      // Optional: if we want to visually align with the batch test, we could find an item 
      // with a similar id and update it, but it's cleaner to just keep single state separate.
    } catch (err: any) {
      setSingleState('FAILED');
      setSingleResult({
        success: false,
        state: 'FAILED',
        latencyMs: Math.round(performance.now() - startTime),
        institutionalSignatureValid: false,
        userSignatureValid: false,
        bindingValid: false,
        error: err.message || 'Simulated unexpected error',
        logs
      });
    }
  }, []);

  const reset = useCallback(() => {
    setSingleState('IDLE');
    setSingleResult(null);
    resetDataset();
  }, [resetDataset]);

  const stats = useMemo(() => {
    let pending = 0;
    let validated = 0;
    let failed = 0;
    let latencySum = 0;

    for (let i = 0; i < items.length; i++) {
      const status = items[i].validationStatus;
      if (status === 'pending' || status === 'in_progress' || status === 'dual_key_in_progress' || status === 'eidas_in_progress') {
        pending++;
      } else if (status === 'validated') {
        validated++;
        latencySum += items[i].simulatedLatencyMs;
      } else if (status === 'failed') {
        failed++;
      }
    }

    return {
      total: items.length,
      pending,
      validated,
      failed,
      avgLatency: validated > 0 ? Math.round(latencySum / validated) : 0
    };
  }, [items]);

  return {
    // --- Single Item Handshake Interface ---
    state: singleState,
    result: singleResult,
    runDualKeyHandshake,
    reset,
    // --- Batch Stress Test Interface ---
    items,
    pendingIds,
    validateItem,
    runStressTest,
    resetDataset,
    stats
  };
}

/**
 * INP Profiling Guide for BILANX DK-SVS React 19 Sandbox:
 * 
 * 1. Enable React StrictMode to verify double-invocations don't break the race-condition guards.
 * 2. Use the React DevTools Profiler to record a stress test (e.g., batch validating 500 items).
 * 3. Observe the "Commit" phases: thanks to `useTransition` and `useActionState`, you will see
 *    that the massive DOM updates required to re-render rows are yielded to the browser,
 *    keeping INP (Interaction to Next Paint) low. The main thread is never blocked for long 
 *    continuous periods, despite the heavy background processing.
 */
