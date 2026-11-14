import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "./api";

export function Login() {
  const client = useQueryClient();
  const [password, setPassword] = useState("");
  const login = useMutation({
    mutationFn: () => api.login(password),
    onSuccess: (session) => {
      client.setQueryData(["session"], session);
      void client.invalidateQueries();
    },
  });
  return (
    <form
      className="card login"
      onSubmit={(e) => {
        e.preventDefault();
        login.mutate();
      }}
    >
      <h2>Log in</h2>
      <label>
        Admin password
        <input
          type="password"
          autoFocus
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </label>
      <button type="submit" disabled={!password || login.isPending}>
        Log in
      </button>
      {login.error && <p className="error">{login.error.message}</p>}
    </form>
  );
}
