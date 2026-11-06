/** Server policy age. The prover does not choose this. */
export const AGE_GATE_POLICY_THRESHOLD = 18;

/**
 * UTF-8 message signed by the user key.
 * proofSha256Hex is lowercase hex SHA-256 of the 1,355-byte proof.
 */
export function clearanceMessage(
  challengeId: string,
  secondFactorHash: string,
  proofSha256Hex: string
): string {
  return `${challengeId}:${secondFactorHash}:${proofSha256Hex}`;
}
