defmodule AshGrant.ScopeThroughTest do
  @moduledoc """
  Tests for the scope_through feature (#62).

  User Story: As a developer, I want child resources to inherit a parent resource's
  instance permissions via a FK relationship, so that `"post:post_abc:read:"`
  automatically grants access to comments with `post_id == post_abc`.
  """
  use AshGrant.DataCase, async: true

  import AshGrant.Test.Generator

  alias AshGrant.Test.ChildComment

  require Ash.Query

  # Helper to create a post in the DB
  defp create_post!(opts) do
    generate(post(opts))
  end

  # Helper to create a child comment in the DB
  defp create_child_comment!(opts) do
    ChildComment
    |> Ash.Changeset.for_create(:create, opts)
    |> Ash.create!(authorize?: false)
  end

  # Helper to read child comments with actor
  defp read_comments(actor) do
    ChildComment
    |> Ash.Query.for_read(:read)
    |> Ash.read!(actor: actor)
  end

  describe "scope_through :post — read filtering (parent instance propagation)" do
    test "parent instance permission grants access to child records" do
      post = create_post!(title: "My Post", author_id: Ash.UUID.generate())

      comment_in_post =
        create_child_comment!(%{body: "In post", post_id: post.id, user_id: Ash.UUID.generate()})

      _comment_elsewhere =
        create_child_comment!(%{
          body: "Elsewhere",
          post_id: Ash.UUID.generate(),
          user_id: Ash.UUID.generate()
        })

      actor = %{id: Ash.UUID.generate(), permissions: ["post:#{post.id}:read:"]}

      comments = read_comments(actor)
      assert length(comments) == 1
      assert hd(comments).id == comment_in_post.id
    end

    test "multiple parent instance permissions see all related children" do
      post1 = create_post!(title: "Post 1", author_id: Ash.UUID.generate())
      post2 = create_post!(title: "Post 2", author_id: Ash.UUID.generate())

      c1 =
        create_child_comment!(%{body: "C1", post_id: post1.id, user_id: Ash.UUID.generate()})

      c2 =
        create_child_comment!(%{body: "C2", post_id: post2.id, user_id: Ash.UUID.generate()})

      _c3 =
        create_child_comment!(%{
          body: "C3",
          post_id: Ash.UUID.generate(),
          user_id: Ash.UUID.generate()
        })

      actor = %{
        id: Ash.UUID.generate(),
        permissions: ["post:#{post1.id}:read:", "post:#{post2.id}:read:"]
      }

      comments = read_comments(actor)
      assert length(comments) == 2
      ids = Enum.map(comments, & &1.id)
      assert c1.id in ids
      assert c2.id in ids
    end

    test "parent deny blocks child access" do
      post = create_post!(title: "Denied Post", author_id: Ash.UUID.generate())

      _comment =
        create_child_comment!(%{body: "Denied", post_id: post.id, user_id: Ash.UUID.generate()})

      actor = %{
        id: Ash.UUID.generate(),
        permissions: ["post:#{post.id}:read:", "!post:#{post.id}:read:"]
      }

      result = ChildComment |> Ash.Query.for_read(:read) |> Ash.read(actor: actor)
      assert {:ok, []} = result
    end

    test "combined RBAC + parent instance permissions (OR logic)" do
      actor_id = Ash.UUID.generate()
      post = create_post!(title: "Specific Post", author_id: Ash.UUID.generate())

      # Comment in the specific post (accessible via parent instance)
      c_in_post =
        create_child_comment!(%{body: "In post", post_id: post.id, user_id: Ash.UUID.generate()})

      # Own comment in another post (accessible via RBAC :own)
      c_own =
        create_child_comment!(%{
          body: "My comment",
          post_id: Ash.UUID.generate(),
          user_id: actor_id
        })

      # Someone else's comment in another post (not accessible)
      _c_other =
        create_child_comment!(%{
          body: "Other",
          post_id: Ash.UUID.generate(),
          user_id: Ash.UUID.generate()
        })

      actor = %{
        id: actor_id,
        permissions: ["child_comment:*:read:own", "post:#{post.id}:read:"]
      }

      comments = read_comments(actor)
      assert length(comments) == 2
      ids = Enum.map(comments, & &1.id)
      assert c_in_post.id in ids
      assert c_own.id in ids
    end

    test "non-matching parent permissions return empty results" do
      post = create_post!(title: "Some Post", author_id: Ash.UUID.generate())

      _comment =
        create_child_comment!(%{body: "Hello", post_id: post.id, user_id: Ash.UUID.generate()})

      # Actor has parent instance for a different post — filter won't match
      actor = %{id: Ash.UUID.generate(), permissions: ["post:#{Ash.UUID.generate()}:read:"]}

      comments = read_comments(actor)
      assert comments == []
    end

    test "no permissions at all returns no rows" do
      post = create_post!(title: "Some Post", author_id: Ash.UUID.generate())

      _comment =
        create_child_comment!(%{body: "Hello", post_id: post.id, user_id: Ash.UUID.generate()})

      actor = %{id: Ash.UUID.generate(), permissions: []}

      result = ChildComment |> Ash.Query.for_read(:read) |> Ash.read(actor: actor)
      assert {:ok, []} = result
    end
  end

  test "child deny excludes a row granted through its parent read permission" do
    post = create_post!(title: "Read parent", author_id: Ash.UUID.generate())

    denied =
      create_child_comment!(%{body: "Denied", post_id: post.id, user_id: Ash.UUID.generate()})

    allowed =
      create_child_comment!(%{body: "Allowed", post_id: post.id, user_id: Ash.UUID.generate()})

    actor = %{
      id: Ash.UUID.generate(),
      permissions: [
        "post:#{post.id}:read:",
        "!child_comment:#{denied.id}:read:"
      ]
    }

    assert Enum.map(read_comments(actor), & &1.id) == [allowed.id]

    wide = %{actor | permissions: ["post:#{post.id}:read:", "!child_comment:*:read:"]}

    assert {:ok, []} =
             ChildComment |> Ash.Query.for_read(:read) |> Ash.read(actor: wide)
  end

  describe "scope_through :post — write actions" do
    test "create denies match the proposed identity without rejecting unrelated new targets" do
      post = create_post!(title: "Create permissions", author_id: Ash.UUID.generate())
      reader = "child_comment:*:read:always"

      unrelated_id = Ash.UUID.generate()

      default_actor = %{
        id: Ash.UUID.generate(),
        permissions: [
          "child_comment:*:create:always",
          "!child_comment:#{unrelated_id}:create:",
          reader
        ]
      }

      assert {:ok, generated} =
               Ash.create(
                 ChildComment,
                 %{
                   body: "Generated identity",
                   post_id: post.id
                 },
               actor: default_actor,
               action: :create
               )

      assert is_binary(generated.id)
      refute generated.id == unrelated_id
      assert {:ok, persisted} = Ash.get(ChildComment, generated.id, actor: default_actor)
      assert persisted.body == "Generated identity"

      for denial <- [:unrelated, :matching, :wide] do
        changeset =
          Ash.Changeset.for_create(ChildComment, :create, %{
            body: "Proposed #{denial}",
            post_id: post.id,
            user_id: Ash.UUID.generate()
          })

        changeset = Ash.Changeset.force_change_attribute(changeset, :id, Ash.UUID.generate())
        id = Ash.Changeset.get_attribute(changeset, :id)
        assert is_binary(id)

        denied_id =
          case denial do
            :unrelated -> Ash.UUID.generate()
            :matching -> id
            :wide -> "*"
          end

        actor = %{
          id: Ash.UUID.generate(),
          permissions: [
            "child_comment:*:create:always",
            "!child_comment:#{denied_id}:create:",
            reader
          ]
        }

        if denial == :unrelated do
          assert {:ok, created} = Ash.create(changeset, actor: actor)
          assert created.id == id
          assert {:ok, persisted} = Ash.get(ChildComment, id, actor: actor)
          assert persisted.body == "Proposed unrelated"
        else
          assert {:error, %Ash.Error.Forbidden{}} = Ash.create(changeset, actor: actor)
          assert {:ok, []} = ChildComment |> Ash.Query.filter(id == ^id) |> Ash.read(actor: actor)
        end
      end
    end

    test "explicit child deny cannot fall through to a parent instance allow" do
      post = create_post!(title: "Parent permission", author_id: Ash.UUID.generate())

      comment =
        create_child_comment!(%{
          body: "Retained original",
          post_id: post.id,
          user_id: Ash.UUID.generate()
        })

      for deny <- ["!child_comment:*:update:", "!child_comment:#{comment.id}:update:"] do
        actor = %{
          id: Ash.UUID.generate(),
          permissions: [
            "post:#{post.id}:update:",
            "child_comment:#{comment.id}:update:",
            deny
          ]
        }

        assert {:error, %Ash.Error.Forbidden{}} =
                 comment
                 |> Ash.Changeset.for_update(:update, %{body: "Must remain denied"})
                 |> Ash.update(actor: actor)

        assert Ash.get!(ChildComment, comment.id, authorize?: false).body == "Retained original"
      end
    end

    test "a current child instance grant allows only its exact update target" do
      post = create_post!(title: "Instance post", author_id: Ash.UUID.generate())

      first =
        create_child_comment!(%{body: "First", post_id: post.id, user_id: Ash.UUID.generate()})

      other =
        create_child_comment!(%{body: "Other", post_id: post.id, user_id: Ash.UUID.generate()})

      actor = %{id: Ash.UUID.generate(), permissions: ["child_comment:#{first.id}:update:"]}

      assert {:ok, updated} =
               first
               |> Ash.Changeset.for_update(:update, %{body: "Updated"})
               |> Ash.update(actor: actor)

      assert updated.body == "Updated"

      assert {:error, %Ash.Error.Forbidden{}} =
               other
               |> Ash.Changeset.for_update(:update, %{body: "Denied"})
               |> Ash.update(actor: actor)

      assert Ash.get!(ChildComment, other.id, authorize?: false).body == "Other"

      wrong_resource = %{actor | permissions: ["other_comment:#{first.id}:update:"]}

      assert {:error, %Ash.Error.Forbidden{}} =
               first
               |> Ash.Changeset.for_update(:update, %{body: "Wrong resource"})
               |> Ash.update(actor: wrong_resource)
    end

    test "atomic bulk update uses the original child instance and honors a child deny" do
      post = create_post!(title: "Atomic post", author_id: Ash.UUID.generate())

      comment =
        create_child_comment!(%{body: "Original", post_id: post.id, user_id: Ash.UUID.generate()})

      actor = %{
        id: Ash.UUID.generate(),
        permissions: [
          "child_comment:*:read:",
          "child_comment:#{comment.id}:update:"
        ]
      }

      query = ChildComment |> Ash.Query.for_read(:read) |> Ash.Query.filter(id == ^comment.id)

      result =
        Ash.bulk_update(query, :update, %{body: "Atomic update"},
          actor: actor,
          strategy: [:atomic, :stream],
          return_records?: true,
          return_errors?: true
        )

      assert result.status == :success
      assert [%{id: id, body: "Atomic update"}] = result.records
      assert id == comment.id

      denied_actor = %{
        actor
        | permissions: actor.permissions ++ ["!child_comment:#{comment.id}:update:"]
      }

      _denied =
        Ash.bulk_update(query, :update, %{body: "Must remain denied"},
          actor: denied_actor,
          strategy: [:atomic, :stream],
          return_errors?: true
        )

      assert Ash.get!(ChildComment, comment.id, authorize?: false).body == "Atomic update"
    end

    test "named child scope and destroy honor the exact instance" do
      post = create_post!(title: "Scoped post", author_id: Ash.UUID.generate())
      owner_id = Ash.UUID.generate()
      owned = create_child_comment!(%{body: "Owned", post_id: post.id, user_id: owner_id})
      sibling = create_child_comment!(%{body: "Sibling", post_id: post.id, user_id: owner_id})
      scoped = %{id: owner_id, permissions: ["child_comment:#{owned.id}:update:own"]}

      assert {:ok, changed} =
               owned
               |> Ash.Changeset.for_update(:update, %{body: "Scoped"})
               |> Ash.update(actor: scoped)

      assert changed.body == "Scoped"

      assert {:error, %Ash.Error.Forbidden{}} =
               sibling
               |> Ash.Changeset.for_update(:update, %{body: "Denied"})
               |> Ash.update(actor: scoped)

      destroyer = %{id: owner_id, permissions: ["child_comment:#{owned.id}:destroy:"]}
      assert {:error, %Ash.Error.Forbidden{}} = Ash.destroy(sibling, actor: destroyer)

      denied_destroyer = %{
        destroyer
        | permissions: [
            "post:#{post.id}:destroy:",
            "!child_comment:#{owned.id}:destroy:"
          ]
      }

      assert {:error, %Ash.Error.Forbidden{}} = Ash.destroy(changed, actor: denied_destroyer)
      assert :ok = Ash.destroy(changed, actor: destroyer)
    end

    test "parent instance permission allows update on matching post" do
      post = create_post!(title: "My Post", author_id: Ash.UUID.generate())

      comment =
        create_child_comment!(%{body: "Original", post_id: post.id, user_id: Ash.UUID.generate()})

      actor = %{id: Ash.UUID.generate(), permissions: ["post:#{post.id}:update:"]}

      result =
        comment
        |> Ash.Changeset.for_update(:update, %{body: "Updated"})
        |> Ash.update(actor: actor)

      assert {:ok, updated} = result
      assert updated.body == "Updated"
    end

    test "parent instance permission denies update on non-matching post" do
      other_post_id = Ash.UUID.generate()
      post = create_post!(title: "Different Post", author_id: Ash.UUID.generate())

      comment =
        create_child_comment!(%{body: "Original", post_id: post.id, user_id: Ash.UUID.generate()})

      # Actor has update permission for a different post
      actor = %{id: Ash.UUID.generate(), permissions: ["post:#{other_post_id}:update:"]}

      result =
        comment
        |> Ash.Changeset.for_update(:update, %{body: "Hacked"})
        |> Ash.update(actor: actor)

      assert {:error, %Ash.Error.Forbidden{}} = result
    end
  end

  describe "scope_through :post — CanPerform calculation" do
    test "can_update? reflects parent instance permissions" do
      post1 = create_post!(title: "Post 1", author_id: Ash.UUID.generate())
      post2 = create_post!(title: "Post 2", author_id: Ash.UUID.generate())

      c1 =
        create_child_comment!(%{
          body: "In post1",
          post_id: post1.id,
          user_id: Ash.UUID.generate()
        })

      c2 =
        create_child_comment!(%{
          body: "In post2",
          post_id: post2.id,
          user_id: Ash.UUID.generate()
        })

      # Actor can read all (RBAC) but only update post1's children
      actor = %{
        id: Ash.UUID.generate(),
        permissions: ["child_comment:*:read:always", "post:#{post1.id}:update:"]
      }

      comments =
        ChildComment
        |> Ash.Query.for_read(:read)
        |> Ash.Query.load([:can_update?])
        |> Ash.read!(actor: actor)

      comments_by_id = Map.new(comments, &{&1.id, &1})
      assert comments_by_id[c1.id].can_update? == true
      assert comments_by_id[c2.id].can_update? == false
    end
  end
end
