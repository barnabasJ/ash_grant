defmodule AshGrant.Transformers.NormalizeGrants do
  @moduledoc """
  Normalizes the `grants` DSL block.

  This transformer runs once all entities are parsed and:

  - Fills in `on:` with the current resource module when omitted on a
    permission declared inside a resource's own `ash_grant` block.
  - **Composes `grants` with an explicit `resolver`**: when a resource declares
    both, the explicit resolver is persisted as the *base resolver*, and
    `AshGrant.GrantsResolver` (wired in by `SynthesizeGrantsResolver`) unions its
    grant-derived permission strings with the base resolver's strings at runtime.
    So the declarative `grants` provide static, structural permissions while the
    explicit resolver keeps supplying dynamic/DB-backed ones — both reach the
    evaluator.

  Reference validation (that each permission's `on:`, `action:`, and `scope:`
  resolve to real things) is handled by
  `AshGrant.Verifiers.ValidateGrantReferences`, which runs after all
  transformers so that Ash's default actions have been materialized.
  """

  use Spark.Dsl.Transformer

  alias Spark.Dsl.Transformer

  # Persisted key under which an explicit `resolver` is stashed when a resource
  # also declares `grants`, so `AshGrant.GrantsResolver` can union the two at
  # runtime. Read at runtime via `Spark.Dsl.Extension.get_persisted/2`.
  @base_resolver_key :ash_grant_base_resolver

  @doc false
  @spec base_resolver_key() :: atom()
  def base_resolver_key, do: @base_resolver_key

  @impl true
  def after?(_), do: false

  @impl true
  def before?(AshGrant.Transformers.SynthesizeGrantsResolver), do: true
  def before?(_), do: false

  @impl true
  def transform(dsl_state) do
    resource = Transformer.get_persisted(dsl_state, :module)
    grants = Transformer.get_entities(dsl_state, [:ash_grant, :grants])

    case grants do
      [] ->
        {:ok, dsl_state}

      _ ->
        dsl_state
        |> persist_base_resolver()
        |> inject_default_resource(resource, grants)
    end
  end

  # When a resource declares BOTH `grants` and an explicit `resolver`, stash the
  # explicit resolver as the base resolver. `SynthesizeGrantsResolver` then
  # overwrites `:resolver` with `AshGrant.GrantsResolver`, which unions the
  # grant-derived strings with this base resolver's strings.
  defp persist_base_resolver(dsl_state) do
    case Transformer.get_option(dsl_state, [:ash_grant], :resolver) do
      nil -> dsl_state
      resolver -> Transformer.persist(dsl_state, @base_resolver_key, resolver)
    end
  end

  defp inject_default_resource(dsl_state, resource, grants) do
    updated = Enum.reduce(grants, dsl_state, &inject_into_grant(&1, &2, resource))
    {:ok, updated}
  end

  defp inject_into_grant(grant, dsl_state, resource) do
    new_permissions = Enum.map(grant.permissions || [], &inject_permission_resource(&1, resource))
    new_grant = %{grant | permissions: new_permissions}

    Transformer.replace_entity(
      dsl_state,
      [:ash_grant, :grants],
      new_grant,
      &(&1.name == grant.name)
    )
  end

  defp inject_permission_resource(%{on: nil} = permission, resource),
    do: %{permission | on: resource}

  defp inject_permission_resource(permission, _resource), do: permission
end
