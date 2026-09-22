import { createHash } from "node:crypto";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { phoneNumber } from "better-auth/plugins/phone-number";
import { account, db, session, user, verification } from "@db";
import { betterAuthBaseURL } from "@shared/environment/origin";
import { env, localPhoneAuthBypassEnabled } from "@shared/environment";
import { getInstallationSecrets } from "@db/services/installation-secrets";
import { LinqDeliveryError, linqOtpFailure, sendLinqText } from "./linq";
import { isE164PhoneNumber } from "@shared/identity/phone-number";

let authPromise: ReturnType<typeof initializeAuth> | undefined;

export function getAuth() {
  authPromise ??= initializeAuthWithRetry();
  return authPromise;
}

async function initializeAuthWithRetry() {
  try {
    return await initializeAuth();
  } catch (error) {
    authPromise = undefined;
    throw error;
  }
}

async function initializeAuth() {
  const { betterAuthSecret } = await getInstallationSecrets();
  const googleProvider =
    env.GOOGLE_CLIENT_ID !== undefined && env.GOOGLE_CLIENT_SECRET !== undefined
      ? {
          clientId: env.GOOGLE_CLIENT_ID,
          clientSecret: env.GOOGLE_CLIENT_SECRET,
        }
      : undefined;
  const githubProvider =
    env.GITHUB_CLIENT_ID !== undefined && env.GITHUB_CLIENT_SECRET !== undefined
      ? {
          clientId: env.GITHUB_CLIENT_ID,
          clientSecret: env.GITHUB_CLIENT_SECRET,
        }
      : undefined;
  const socialSignInEnabled =
    googleProvider !== undefined || githubProvider !== undefined;
  return betterAuth({
    appName: "Local Vault Assistant",
    baseURL: betterAuthBaseURL(),
    database: drizzleAdapter(db, {
      provider: "pg",
      schema: { account, session, user, verification },
    }),
    databaseHooks: {
      user: {
        create: {
          before: async (newUser) => {
            // Phone sign-up creates users with synthetic local addresses.
            if (newUser.email.endsWith("@local-vault.invalid")) {
              return { data: newUser };
            }
            // Social sign-up is limited to this deployment's owner.
            const ownerEmail = env.OWNER_EMAIL?.trim().toLowerCase();
            if (
              ownerEmail === undefined ||
              newUser.email.trim().toLowerCase() !== ownerEmail
            ) {
              throw new APIError("FORBIDDEN", {
                code: "ACCOUNT_NOT_ALLOWED",
                message:
                  "This deployment only allows the owner's account to sign in.",
              });
            }
            return { data: newUser };
          },
        },
      },
    },
    disabledPaths: [
      "/change-email",
      "/request-password-reset",
      "/reset-password",
      "/reset-password/:token",
      "/send-verification-email",
      "/sign-in/email",
      ...(socialSignInEnabled ? [] : ["/sign-in/social"]),
      "/sign-up/email",
      "/verify-email",
    ],
    socialProviders: socialSignInEnabled
      ? {
          ...(githubProvider ? { github: githubProvider } : {}),
          ...(googleProvider ? { google: googleProvider } : {}),
        }
      : undefined,
    plugins: [
      phoneNumber({
        allowedAttempts: 3,
        expiresIn: 300,
        phoneNumberValidator: isE164PhoneNumber,
        requireVerification: true,
        sendOTP: localPhoneAuthBypassEnabled
          ? () => undefined
          : ({ code, phoneNumber: to }) => sendPhoneCode({ code, to }),
        signUpOnVerification: {
          getTempEmail: (phoneNumberValue) =>
            `phone-${createHash("sha256")
              .update(phoneNumberValue)
              .digest("hex")}@local-vault.invalid`,
          getTempName: () => "Phone user",
        },
        verifyOTP: localPhoneAuthBypassEnabled
          ? ({ phoneNumber: value }) => isE164PhoneNumber(value)
          : undefined,
      }),
    ],
    secret: betterAuthSecret,
  });
}

export async function sendPhoneCode({
  code,
  to,
}: {
  readonly code: string;
  readonly to: string;
}) {
  if (!env.LINQ_CONNECTOR) {
    throw new APIError("SERVICE_UNAVAILABLE", {
      code: "LINQ_NOT_CONFIGURED",
      message:
        "iMessage sign-in is not configured. Attach a Linq connector to this deployment.",
    });
  }

  try {
    await sendLinqText({
      connector: env.LINQ_CONNECTOR,
      idempotencyKey: `auth-otp-${createHash("sha256")
        .update(`${to}\u0000${code}`)
        .digest("hex")}`,
      message: `Local Vault Assistant sign-in code: ${code}. Expires in 5 minutes.`,
      to,
    });
  } catch (error) {
    if (error instanceof LinqDeliveryError) {
      const failure = linqOtpFailure(error);
      throw new APIError("BAD_GATEWAY", {
        code: failure.code,
        linqError: {
          code: error.code,
          message: error.linqMessage,
          status: error.status,
          trace_id: error.traceId,
        },
        message: failure.message,
      });
    }

    throw new APIError("BAD_GATEWAY", {
      code: "LINQ_CONNECTOR_UNAVAILABLE",
      message:
        "This deployment cannot access its Linq connector. Check LINQ_CONNECTOR and the connector's Vercel project attachment.",
    });
  }
}
