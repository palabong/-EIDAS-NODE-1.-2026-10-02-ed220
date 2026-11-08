/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import { getErrorMessage } from '../httpShared.ts';
import { verifyStockRequest } from '../rfidCatalog.ts';

export function mountStockRoutes(app: express.Express): void {
  app.post('/api/v1/stock/verify', async (req, res) => {
    try {
      const body = req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)
        ? req.body as Record<string, unknown>
        : {};
      const hardwareUid = typeof body.hardwareUid === 'string' ? body.hardwareUid : undefined;
      const productName = typeof body.productName === 'string' ? body.productName : undefined;
      const decision = await verifyStockRequest({ hardwareUid, productName });
      res.status(200).json(decision);
    } catch (error: unknown) {
      console.error('[Stock Verify] Error:', getErrorMessage(error));
      res.status(500).json({ ok: false, reason: 'verification_error', signatureVerified: false });
    }
  });
}
