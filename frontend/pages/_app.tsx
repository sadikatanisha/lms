import type { AppProps } from "next/app";
import { useEffect } from "react";
import { apiSlice } from "../redux/features/api/apiSlice";
import { store } from "../redux/store";

import { Providers } from "../app/Provider";
const initializeApp = async () => {
  try {
    // Dispatch loadUser to fetch the user profile and set state
    await store.dispatch(
      apiSlice.endpoints.loadUser.initiate(undefined, { forceRefetch: true })
    );
  } catch (error) {
    console.error("Error initializing app:", error);
  }
};

export default function MyApp({ Component, pageProps }: AppProps) {
  useEffect(() => {
    initializeApp();
  }, []);

  return (
    <Providers>
      <Component {...pageProps} />
    </Providers>
  );
}
