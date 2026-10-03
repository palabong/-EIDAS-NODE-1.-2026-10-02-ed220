import { useBilanxDualKeyValidationReal } from './useBilanxDualKeyValidation.real';
import { useBilanxDualKeyValidation as useMock } from '../mocks/useBilanxDualKeyValidation.mock';

import type {
  HandshakeState,
  DualKeyValidationResult,
} from './useBilanxDualKeyValidation.real';

export type { HandshakeState, DualKeyValidationResult };

export interface UseDualKeyValidationConfig {
  useRealCrypto?: boolean;
}

export interface DualKeyValidationInterface {
  state: HandshakeState;
  result: DualKeyValidationResult | null;
  runDualKeyHandshake: (params: {
    institutionId: string;
    secondFactorId: string;
  }) => Promise<void>;
  reset: () => void;
  resetKeys?: () => Promise<void>;
  isUsingPersistentKeys?: boolean;
}

/**
 * useDualKeyValidation
 *
 * Clean routing hook between the real Web Crypto implementation and the mock.
 * Both underlying hooks are always called to respect React's Rules of Hooks.
 */
export function useDualKeyValidation(
  config: UseDualKeyValidationConfig = {}
): DualKeyValidationInterface {
  const { useRealCrypto = false } = config;

  // Always call both hooks to comply with React Rules of Hooks.
  // This is safe and preferred over conditional hook calls.
  const real = useBilanxDualKeyValidationReal();
  const mock = useMock() as any;

  if (useRealCrypto) {
    return {
      state: real.state,
      result: real.result,
      runDualKeyHandshake: real.runDualKeyHandshake,
      reset: real.reset,
      resetKeys: real.resetKeys,
      isUsingPersistentKeys: real.isUsingPersistentKeys
    };
  }

  // Return mock implementation (with adapter if needed)
  return {
    state: mock.state,
    result: mock.result,
    runDualKeyHandshake: mock.runDualKeyHandshake ?? (async () => {
      console.warn('[useDualKeyValidation] Mock does not implement runDualKeyHandshake yet');
    }),
    reset: mock.reset ?? (() => {}),
  };
}
