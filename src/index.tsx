import { useReducerWithEffects } from "usables";
import dayjs from "dayjs";
import jwtDecode from "jwt-decode";
import React, { createContext, useContext } from "react";

export interface AuthTokens {
  refreshToken: string;
  accessToken: string;
}

export interface DecodedJWT {
  data: {
    isImpersonated: boolean;
    token: string;
    userId: string;
  };
  email: string;
  exp: number;
  expDate: Date;
  iat: number;
  iatDate: Date;
  userId: number;
}

export interface Storage<T = object> {
  load: () => Promise<T> | T;
  save: (tokens: T) => Promise<void> | void;
  clear: () => Promise<void> | void;
}

export function isTokenExpired(token: string) {
  if (!token) {
    return true;
  }
  const decodedAccessToken = decode<DecodedJWT>(token);
  return dayjs().isAfter(decodedAccessToken.expDate);
}

export interface AuthProviderOptions<TAuthState, TAuthenticatedUser> {
  onError?(error: Error): void;
  storage?: Storage<TAuthState>;
  shouldRefreshAuthState?(authState: TAuthState): boolean;
  getUser?(authState: TAuthState): TAuthenticatedUser | null;
  isValidAuthState?(authState: TAuthState): boolean;
  refreshAuthState?(authState: TAuthState): Promise<TAuthState> | TAuthState;
}

export interface UseAuthContext<TAuthState, TAuthenticatedUser> {
  dispatch: (action: { [key: string]: any; type: string }) => void;
  isSignedIn: boolean;
  isSignedOut: boolean;
  isLoading: boolean;
  signOut: () => void;
  signIn: (authState: TAuthState) => void;
  status: "loading" | "signed_in" | "signed_out";
  authState: TAuthState | null;
  user: TAuthenticatedUser | null;
}

export function useAuthState<TAuthState, TAuthenticatedUser>({
  onError = (error) => console.warn(error),
  storage,
  refreshAuthState,
  shouldRefreshAuthState,
  getUser,
  isValidAuthState,
}: AuthProviderOptions<TAuthState, TAuthenticatedUser>): UseAuthContext<
  TAuthState,
  TAuthenticatedUser
> {
  const [state, dispatch] = useReducerWithEffects(
    (prevState, action, exec) => {
      switch (action.type) {
        case "SIGN_IN":
          if (refreshAuthState && shouldRefreshAuthState?.(action.authState)) {
            exec({
              type: "refreshAuthState",
              authState: action.authState,
            });
            return {
              ...prevState,
              authState: null,
              status: "loading",
            } as const;
          }

          if (isValidAuthState && !isValidAuthState(action.authState)) {
            exec({
              type: "clearAuthState",
            });
            return {
              ...prevState,
              authState: null,
              status: "signed_out",
            } as const;
          }

          exec({
            type: "saveAuthState",
            authState: action.authState,
          });
          return {
            ...prevState,
            status: "signed_in",
            authState: action.authState,
            user: getUser?.(action.authState) ?? null,
          } as const;
        case "NO_TOKEN_FOUND":
          return {
            ...prevState,
            status: "signed_out",
            tokens: null,
            user: null,
          } as const;
        case "LOAD_AUTH_STATE":
          exec({
            type: "loadAuthState",
          });
          return {
            ...prevState,
            status: "loading",
            authState: null,
            user: null,
          } as const;
        case "SIGN_OUT":
          exec({
            type: "clearAuthState",
          });
          return {
            ...prevState,
            status: "signed_out",
            authState: null,
            user: null,
          } as const;
        default:
          return prevState;
      }
    },
    {
      status: "loading" as "signed_in" | "loading" | "signed_out",
      authState: null as null | TAuthState,
      user: null as null | TAuthenticatedUser,
    },
    {
      saveAuthState: (_, effect, dispatch) => {
        storage?.save(effect.tokens);
      },
      clearAuthState: (_, effect, dispatch) => {
        storage?.clear();
      },
      refreshAuthState: async (_, effect, dispatch) => {
        try {
          const refeshedTokens = await refreshAuthState?.(effect.tokens);
          if (refeshedTokens) {
            dispatch({
              type: "SIGN_IN",
              tokens: refeshedTokens,
            });
          } else {
            onError?.(new Error("No tokens found!"));
            dispatch({ type: "SIGN_OUT" });
          }
        } catch (e) {
          onError?.(e);
          dispatch({ type: "SIGN_OUT" });
        }
      },
      loadAuthState: async (_, effect, dispatch) => {
        try {
          const item = await storage?.load();
          if (item) {
            dispatch({
              type: "SIGN_IN",
              tokens: item,
            });
          } else {
            dispatch({
              type: "NO_TOKEN_FOUND",
            });
          }
        } catch (e) {
          onError?.(e);
          dispatch({
            type: "NO_TOKEN_FOUND",
          });
        }
      },
    } as const
  );

  React.useEffect(() => {
    dispatch({ type: "LOAD_AUTH_STATE" });
  }, [dispatch]);

  return {
    ...state,
    dispatch,
    isSignedIn: state.status === "signed_in",
    isSignedOut: state.status === "signed_out",
    isLoading: state.status === "loading",
    signOut: () => dispatch({ type: "SIGN_OUT" }),
    signIn: (authState: TAuthState) => dispatch({ type: "SIGN_IN", authState }),
  };
}

export const AuthContext = createContext<
  UseAuthContext<AuthTokens, DecodedJWT> | undefined
>(undefined);

export function useJWTAuthState(
  props: AuthProviderOptions<AuthTokens, DecodedJWT>
) {
  return useAuthState<AuthTokens, DecodedJWT>({
    getUser: (tokens) => decode(tokens.accessToken),
    isValidAuthState: (tokens) => !isTokenExpired(tokens.accessToken),
    shouldRefreshAuthState: (tokens) =>
      isTokenExpired(tokens?.accessToken) &&
      !isTokenExpired(tokens?.refreshToken),
    ...props,
  });
}

export const JWTAuthProvider = ({
  children,
  refreshTokens,
  ...props
}: React.PropsWithChildren<
  AuthProviderOptions<AuthTokens, DecodedJWT> & {
    refreshTokens: AuthProviderOptions<
      AuthTokens,
      DecodedJWT
    >["refreshAuthState"];
  }
>) => {
  const context = useJWTAuthState({
    ...props,
    refreshAuthState: refreshTokens,
  });
  return (
    <AuthContext.Provider value={context}>{children}</AuthContext.Provider>
  );
};

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    console.warn("Wrap you app in an AuthProvider!");
  }
  return context;
}

function decode<T>(jwt: string): T {
  const payload: any = jwtDecode(jwt);
  return {
    ...payload,
    expDate: new Date(payload.exp * 1000),
    iatDate: new Date(payload.iat * 1000),
  };
}
