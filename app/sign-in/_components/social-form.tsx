"use client";

import { useMutation } from "@tanstack/react-query";
import { authClient } from "@web/auth/client";
import { Button } from "@web/components/ui/button";
import { FieldError, FieldGroup } from "@web/components/ui/field";

export function SocialSignInButton({
  callbackUrl,
  provider,
}: {
  readonly callbackUrl: string;
  readonly provider: "github" | "google";
}) {
  const label = provider === "github" ? "GitHub" : "Google";
  const signIn = useMutation({
    mutationFn: async () => {
      const result = await authClient.signIn.social({
        callbackURL: callbackUrl,
        provider,
      });
      if (result.error) {
        throw new Error(
          result.error.message ?? `Unable to sign in with ${label}.`
        );
      }
    },
  });

  return (
    <FieldGroup>
      <FieldError errors={signIn.error ? [signIn.error] : undefined} />
      <Button
        className="w-full"
        disabled={signIn.isPending}
        onClick={() => signIn.mutate()}
        size="lg"
        type="button"
      >
        {signIn.isPending
          ? `Redirecting to ${label}…`
          : `Continue with ${label}`}
      </Button>
    </FieldGroup>
  );
}
