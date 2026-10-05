export type RamonaResult = {
  decision: "ALLOW" | "REFUSE";
  reasons: string[];
  runtime_hash: string;
};
