import React, { createContext, useContext, useState, ReactNode } from 'react';
import type { DualKeyValidationResult } from '../hooks/useBilanxDualKeyValidation.real';

export interface DualKeyResultContextType {
  result: DualKeyValidationResult | null;
  setResult: (result: DualKeyValidationResult | null) => void;
  lastUpdated?: number;
}

const DualKeyResultContext = createContext<DualKeyResultContextType>({
  result: null,
  setResult: () => {},
  lastUpdated: 0,
});

export function DualKeyResultProvider({ children }: { children: ReactNode }) {
  const [result, setResultState] = useState<DualKeyValidationResult | null>(null);
  const [lastUpdated, setLastUpdated] = useState<number>(0);

  const setResult = (r: DualKeyValidationResult | null) => {
    setResultState(r);
    setLastUpdated(Date.now());
  };

  return (
    <DualKeyResultContext.Provider value={{ result, setResult, lastUpdated }}>
      {children}
    </DualKeyResultContext.Provider>
  );
}

export function useDualKeyResult() {
  return useContext(DualKeyResultContext);
}
