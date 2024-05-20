import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";
import { userLoggedIn, userLoggedOut } from "../auth/authSlice";

export interface AuthState {
  user: string | null;
  token: string | null;
}

export interface RootState {
  auth: AuthState;
}

const api = process.env.NEXT_PUBLIC_SERVER_URI;

export const apiSlice = createApi({
  reducerPath: "api",
  baseQuery: fetchBaseQuery({
    baseUrl: `${api}/api/v1/`,
    credentials: "include" as const,
    // prepareHeaders: (headers, { getState }) => {
    //   const state = getState() as RootState;
    //   const token = state.auth.token;
    //   if (token) {
    //     headers.set("Authorization", `Bearer ${token}`);
    //   }
    //   return headers;
    // },
  }),
  endpoints: (builder) => ({
    refreshToken: builder.query({
      query: () => ({
        url: "refresh-token",
        method: "GET",
      }),
    }),
    loadUser: builder.query({
      query: (data) => ({
        url: "me",
        method: "GET",
        credentials: "include" as const,
      }),
      async onQueryStarted(args, { queryFulfilled, dispatch }) {
        try {
          const result = await queryFulfilled;
          console.log("Loaduser api", result.data.user);
          dispatch(
            userLoggedIn({
              accessToken: result.data.accessToken,
              user: result.data.user,
            })
          );
        } catch (error: any) {
          console.error("Error loading user:", error);
          if (error.error?.status === 401) {
            dispatch(userLoggedOut());
          }
        }
      },
    }),
  }),
});

export const { useLoadUserQuery, useRefreshTokenQuery } = apiSlice;
