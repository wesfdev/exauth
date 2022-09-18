defmodule ExauthWeb.AuthController do
  @moduledoc """
  ExauthWeb.AuthController
  """

  use ExauthWeb, :controller

  import Ecto.Query, warn: false
  import Plug.Conn

  alias Exauth.Accounts
  alias ExauthWeb.Utils.Util
  alias Exauth.Accounts.User
  alias ExauthWeb.JwtToken
  alias Exauth.AuthTokens.AuthToken
  alias Exauth.Repo

  require Logger

  def ping(conn, _params), do: conn |> render("ack.json", %{message: "pong"})

  def register(conn, params) do
    case Accounts.create_user(params) do
      {:ok, room} ->
        Logger.info("Account created: #{inspect(room)}")

        conn
        |> render("ack.json", %{message: "Account created"})

      {:error, %Ecto.Changeset{errors: errors} = changeset} ->
        Logger.info("ChangeSet: #{inspect(errors)}")

        conn
        |> render("errors.json", %{errors: Util.format_changeset_errors(changeset)})

      others ->
        conn
        |> render("errors.json", %{errors: ["#{inspect(others)}"]})
    end
  end

  def login(conn, params) do
    username = get_username(params)
    password = params["password"]

    with %User{} = user <- Accounts.get_user_by_username(username),
         true <- Pbkdf2.verify_pass(password, user.password) do
      conn |> render("ack.json", %{success: true, data: %{token: gen_token(user)}})
    else
      _ -> conn |> render("errors.json", %{errors: ["Invalid credentials"]})
    end
  end

  def get(conn, _params) do
    conn |> render("ack.json", %{data: conn.assigns.current_user})
  end

  def logout(conn, _params) do
    case Ecto.build_assoc(conn.assigns.current_user, :auth_tokens, %{token: get_token(conn)})
         |> Repo.insert!() do
      %AuthToken{} -> conn |> render("ack.json", %{message: "Logged Out"})
      _ -> conn |> render("errors.json", %{error: ["Internal server error"]})
    end
  end

  defp get_username(%{"username" => nil}), do: nil

  defp get_username(%{"username" => username}) do
    String.downcase(username)
  end

  defp gen_token(user) do
    extra_claims = %{user_id: user.id}
    {:ok, token, _claims} = JwtToken.generate_and_sign(extra_claims)
    token
  end

  defp get_token(conn) do
    bearer = get_req_header(conn, "authorization") |> List.first()

    if bearer == nil do
      ""
    else
      bearer |> String.split(" ") |> List.last()
    end
  end

  defp eval_authorization(bearer) when is_nil(bearer), do: ""

  defp eval_authorization(bearer), do: bearer |> String.split(" ") |> List.last()
end
