defmodule ExauthWeb.Utils.Util do
  @moduledoc """
    ExauthWeb.Utils.Util
  """

  @doc """
  Format changeset errors
  """
  def format_changeset_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, &error_to_map(&1))
    |> Enum.map(fn {key, value} -> "#{key} #{value}" end)
  end

  defp error_to_map({msg, opts}) do
    Enum.reduce(opts, msg, fn {key, value}, acc ->
      String.replace(acc, "%{#{key}}", to_string(value))
    end)
  end
end
