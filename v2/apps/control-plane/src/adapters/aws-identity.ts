import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";

export type AwsIdentity = { accountId: string; partition: string; principalArn: string; validatedAt: string };
export interface AwsIdentityAdapter { validate(): Promise<AwsIdentity>; }

export class StsAwsIdentityAdapter implements AwsIdentityAdapter {
  async validate(): Promise<AwsIdentity> {
    const client = new STSClient({});
    try {
      const response = await client.send(new GetCallerIdentityCommand({}));
      if (!response.Account || !response.Arn) throw new Error("AWS STS did not return account identity");
      return { accountId: response.Account, partition: response.Arn.split(":")[1] ?? "aws", principalArn: response.Arn, validatedAt: new Date().toISOString() };
    } finally { client.destroy(); }
  }
}

export class FakeAwsIdentityAdapter implements AwsIdentityAdapter {
  async validate(): Promise<AwsIdentity> { return { accountId: "000000000000", partition: "aws", principalArn: "arn:aws:iam::000000000000:role/infractory-fake", validatedAt: new Date().toISOString() }; }
}
