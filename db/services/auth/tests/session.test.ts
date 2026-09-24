/* oxlint-disable vitest/require-mock-type-parameters -- Session lookup needs a deliberately partial Better Auth fixture. */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getAuthSession } from "@db/services/auth/session";
import { authSessionFor } from "@tests/helpers/auth-session";

const mocks = vi.hoisted(() => ({ getAuth: vi.fn(), getSession: vi.fn() }));

vi.mock("@db/services/auth", () => ({ getAuth: mocks.getAuth }));

beforeEach(() => {
  vi.clearAllMocks();
  mocks.getAuth.mockResolvedValue({
    api: { getSession: mocks.getSession },
  });
});

describe("auth session", () => {
  it("accepts sessions with a user id and email, phone fields optional", async () => {
    const phoneUser = authSessionFor({
      id: "user-1",
      phoneNumber: "+12025550123",
      phoneNumberVerified: true,
    });
    const socialUser = authSessionFor({ id: "user-2" });
    mocks.getSession
      .mockResolvedValueOnce(phoneUser)
      .mockResolvedValueOnce(socialUser)
      .mockResolvedValueOnce({
        session: socialUser.session,
        user: { email: "" },
      })
      .mockResolvedValueOnce(null);

    const headers = new Headers();
    await expect(getAuthSession(headers)).resolves.toEqual(phoneUser);
    await expect(getAuthSession(headers)).resolves.toEqual(socialUser);
    await expect(getAuthSession(headers)).resolves.toBeNull();
    await expect(getAuthSession(headers)).resolves.toBeNull();
  });
});
