import { postJson } from './client';

export type LoginPayload = {
  email: string;
  password: string;
};

export type LoginResponse = {
  access_token?: string;
  refresh_token?: string;
  message?: string;
};

export type VerifyOtpPayload = {
  email: string;
  code: string;
};

export type VerifyOtpResponse = {
  access_token: string;
  refresh_token: string;
};

export type RefreshTokenPayload = {
  refresh_token: string;
};

export type RefreshTokenResponse = {
  access_token: string;
  refresh_token: string;
};

export type ResendOtpPayload = {
  email: string;
};

export type ResendOtpResponse = {
  message: string;
};

export type SignupPayload = {
  first_name: string;
  last_name: string;
  email: string;
  password: string;
  role_code: string;
};

export type SignupResponse = {
  message: string;
};

export async function login(payload: LoginPayload, signal?: AbortSignal) {
  return postJson<LoginResponse, LoginPayload>('/auth/login', payload, {
    signal,
  });
}

export async function verifyOtp(payload: VerifyOtpPayload, signal?: AbortSignal) {
  return postJson<VerifyOtpResponse, VerifyOtpPayload>('/auth/verify-otp', payload, { signal });
}

export async function resendOtp(payload: ResendOtpPayload, signal?: AbortSignal) {
  return postJson<ResendOtpResponse, ResendOtpPayload>('/auth/resend-otp', payload, { signal });
}

export async function refreshToken(payload: RefreshTokenPayload, signal?: AbortSignal) {
  return postJson<RefreshTokenResponse, RefreshTokenPayload>('/auth/refresh', payload, { signal });
}

export async function signupAssistant(token: string, payload: SignupPayload, signal?: AbortSignal) {
  return postJson<SignupResponse, SignupPayload>('/auth/signup', payload, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    signal,
  });
}
