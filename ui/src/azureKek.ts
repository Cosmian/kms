export const azureKekTags = (kid: string): string[] => ["azure", `kid:${kid}`];
export const azureKekKeyUsage: string[] = ["WrapKey", "Encrypt"];
