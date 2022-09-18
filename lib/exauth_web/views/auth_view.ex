defmodule ExauthWeb.AuthView do
  use ExauthWeb, :view

  def render("ack.json", %{message: message}) do
    %{success: true, message: message}
  end

  def render("ack.json", %{data: data}) do
    %{success: true, data: data}
  end

  def render("errors.json", %{errors: errors}) do
    %{success: false, errors: errors}
  end
end
