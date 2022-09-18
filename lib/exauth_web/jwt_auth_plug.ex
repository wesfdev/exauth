defmodule ExauthWeb.JwtAuthPlug do
  import Plug.Conn
  alias Exauth.Accounts
  alias Exauth.Accounts.User
  alias Exauth.AuthTokens

  def init(opts), do: opts

  def call(conn, _) do
    IO.inspect(get_req_header(conn, "authorization"))
    bearer = get_req_header(conn, "authorization") |> List.first()
    eval_authorization(conn, bearer)
  end

  defp eval_authorization(conn, bearer) when is_nil(bearer) do
    send_401(conn, nil)
  end

  defp eval_authorization(conn, bearer) do
    token = get_token(bearer)

    with {:ok, %{"user_id" => user_id}} <-
           ExauthWeb.JwtToken.verify_and_validate(token),
         %User{} = user <- Accounts.get_user(user_id) do
      auth_token = AuthTokens.get_auth_token_by_token(token)

      if is_nil(auth_token) do
        conn |> assign(:current_user, user)
      else
        send_401(conn, nil)
      end
    else
      {:error, _reason} -> send_401(conn, nil)
      _ -> send_401(conn, nil)
    end
  end

  defp get_token(bearer) do
    bearer |> String.split(" ") |> List.last()
  end

  defp send_401(
         conn,
         data \\ %{message: "Please make sure you have authentication header"}
       ) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, [])
    |> halt
  end
end
