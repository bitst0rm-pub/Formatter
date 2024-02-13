# https://hexdocs.pm/elixir/Code.html#format_string!/2
# Update: 2024-02-13

[
  # The line length to aim for when formatting the document.
  # Defaults to 98. Note that this value is used as a guideline but may not be enforced in all situations.
  line_length: 98,

  # A keyword list of name and arity pairs that should be kept without parentheses whenever possible.
  # The arity may be the atom :*, which implies all arities of that name.
  # The formatter already includes a list of functions, and this option augments that list.
  locals_without_parens: [],

  # When true, converts all inline usages of do: ..., else: ... and friends into do-end blocks.
  # Defaults to false. Note that this option is convergent: once set to true, all keywords will be converted.
  # If set to false later on, do-end blocks won't be converted back to keywords.
  force_do_end_blocks: false,

  # When true, removes unnecessary parentheses in known bitstring modifiers.
  # For example, <<foo::binary()>> becomes <<foo::binary>>, or adds parentheses for custom modifiers,
  # where <<foo::custom_type>> becomes <<foo::custom_type()>>.
  # Defaults to true. This option changes the AST.
  normalize_bitstring_modifiers: true,

  # When true, formats charlists as ~c sigils.
  # For example, 'foo' becomes ~c"foo".
  # Defaults to true. This option changes the AST.
  normalize_charlists_as_sigils: true
]
