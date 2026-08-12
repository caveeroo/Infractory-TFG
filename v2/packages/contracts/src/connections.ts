import { Type, type Static } from "@sinclair/typebox";
import { IsoDateTime, NonEmptyString, Uuid } from "./common.js";

export const AwsConnection = Type.Object({
  id: Uuid,
  name: NonEmptyString,
  accountId: Type.String({ pattern: "^[0-9]{12}$" }),
  partition: Type.String(),
  principalArn: Type.String(),
  validatedAt: IsoDateTime,
  createdAt: IsoDateTime
});
export const CreateAwsConnectionRequest = Type.Object({ name: NonEmptyString }, { additionalProperties: false });
export const ValidateAwsConnectionResponse = Type.Object({ accountId: Type.String(), partition: Type.String(), principalArn: Type.String(), validatedAt: IsoDateTime });
export type AwsConnection = Static<typeof AwsConnection>;
