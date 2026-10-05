export type ArmResult = {
  decision: "ALLOW" | "REFUSE" | "HOLD";
  reasons: string[];
  release_hash: string;
  projected_total_cost_usd: number;
  allowed_cost_usd: number;
  prevented_cost_usd: number;
};
