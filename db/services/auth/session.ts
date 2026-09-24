import { z } from "zod";
import { getAuth } from "@db/services/auth";

// Social sign-in users (GitHub/Google) carry an email and no phone fields;
// phone users carry phoneNumber + phoneNumberVerified plus a synthetic email.
// Both shapes are valid sessions. Sign-in itself is restricted to this
// deployment's owner by the user-creation hook in db/services/auth/index.ts.
const authenticatedSessionSchema = z
  .object({
    user: z
      .object({
        id: z.string().min(1),
        email: z.string().min(1),
        phoneNumber: z.string().min(1).nullish(),
        phoneNumberVerified: z.literal(true).nullish(),
      })
      .loose(),
  })
  .loose();

export async function getAuthSession(headers: Headers) {
  const auth = await getAuth();
  const session = await auth.api.getSession({ headers });
  const parsed = authenticatedSessionSchema.safeParse(session);
  return parsed.success ? parsed.data : null;
}
