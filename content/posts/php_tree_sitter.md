+++
title = "How to do win your PHP source code audit - the modern way"
date = "2023-10-04"
aliases = ["PHP SAST"]
[ author ]
  name = "m1tz"
+++

# How to do win your PHP source code audit - the modern way
Nowadays source code audits are often assisted by code analysis engines, such as [CodeQL](https://codeql.github.com/). However, CodeQL requires for compiled languages a buildable environment that is often not given. As of the day of writing, no PHP language support was added to CodeQL and thus an alternative has to be found.
During the long weekend, I deep-dived into [Tree-sitter](https://tree-sitter.github.io/) a parser generator tool with support for various languages. Thankfully Tree-sitter can be used from Python and the [PHP grammar](https://github.com/tree-sitter/tree-sitter-php) is available officially. This sounds like a nice fit for our use case.

Previous research on this topic was done by [@TheLaluka](https://twitter.com/TheLaluka) in this [video](https://www.youtube.com/watch?v=tlxP4HvzfFA)

# Basics
Tree-sitter parses code based on implemented code grammars and builds syntax trees out of nodes, which can then be queried and traversed. These trees are structured as so-called [S-expressions](https://en.wikipedia.org/wiki/S-expression) which is a notation for tree-structured data. As an example, the following PHP snippet is parsed into the aforementioned structure:

```php
<?php

$bla = "test";
echo $bla;

# Vuln sink
eval($_REQUEST["asdf"]);

function get($name)
{
  echo "something"
}

```

Which results in the *sexpr* or *sexp* tree structure:
```
(program
  (php_tag)
  (expression_statement
    (assignment_expression
      left: (variable_name (name))
      right: (encapsed_string (string_value))
    )
  )
  (echo_statement
    (variable_name (name))
  )
  (comment)
  (expression_statement
    (function_call_expression
      function: (name)
      arguments: (arguments
        (argument
          (subscript_expression
            (variable_name (name))
            (encapsed_string (string_value))
          )
        )
      )
    )
  )
  (function_definition
    name: (name)
    parameters: (formal_parameters
      (simple_parameter
        name: (variable_name (name))
      )
    )
    body: (compound_statement
      (echo_statement
        (encapsed_string (string_value))
        (MISSING ";")
      )
    )
  )
)
```
Tree-sitter leverages this structure and thus can parse the source code appropriately. Compared to Regex-based approaches the already available PHP grammar provides much more accurate parsing that is less error-prone.

## Syntax Nodes
In Python this results in a list of nodes with sub-nodes, sub-sub-nodes, etc.

```plaintext
[
  <Node type=php_tag, start_point=(0, 0), end_point=(0, 5)>,
  <Node type=expression_statement, start_point=(2, 0), end_point=(2, 14)>,
  <Node type=echo_statement, start_point=(3, 0), end_point=(3, 10)>,
  <Node type=comment, start_point=(5, 0), end_point=(5, 11)>,
  <Node type=expression_statement, start_point=(6, 0), end_point=(6, 24)>,
  <Node type=function_definition, start_point=(8, 0), end_point=(11, 1)>
]
```
There are plenty of node types, such as:
```
expression_statement
binary_expression
compound_statement
assignment_expression
class_declaration
interface_declaration
parenthesized_expression
namespace_use_declaration
require_once_expression
namespace_definition
echo_statement
function_definition
function_call_expression
if_statement
comment
php_tag
argument_list
text_interpolation
final_modifier
class
name
base_clause
class_interface_clause
declaration_list
formal_parameters
visibility_modifier
...
```

## Node Field Names
Many grammars assign unique field names to particular nodes to make nodes easier to analyze. That's the same with the provided PHP grammar, for example, with `function_call_node.child_by_field_name("arguments")`. There are a few fields that I know of:
```
name
parameters
arguments
body
return_type
```


# Queries
After some basics, it is finally time to write some queries that support in source code analysis. As an example, we take a typical security pitfall such as the `add_action('admin_init', [CALLBACK_FUNCTION]);` from WordPress. A common misunderstanding is that the callback of the hook is called whenever a user, authenticated as admin, visits an administrative page. This might sound appropriate, however, the hook is triggered upon any page visit on path `/wp-admin/*` unauthenticated. For attackers, the callback is pretty interesting as it can execute code unauthorized context if no checks are implemented properly.
Tree-sitter assists in finding these vulnerable sources with node types *function_call_expression*. This means we have to walk the tree of nodes and stop by this type, get the *function* field with `node.child_by_field_name("function")`, and obtain the *start_byte* and *end_byte*. With this information, we can obtain the name of the function with Python's slicing mechanism that is applied to the source code with `file_content[node.child_by_field_name("function").start_byte:node.child_by_field_name("function").end_byte].decode()`. The same can be applied with arguments `node.child_by_field_name("arguments")`, resulting in a list of arguments from that specific function.

Putting all together results in the following Python snippet:

```python
def extract_function_name(node, file_content):
  return file_content[node.child_by_field_name("function").start_byte:node.child_by_field_name("function").end_byte].decode()

def extract_function_calls(php_file, node, extracts, file_content, name_match=None):
  if node.type == "function_call_expression":
    function_name = extract_function_name(node, file_content)
    if name_match is not None:
      if not name_match in function_name:
        return
    arguments = node.child_by_field_name("arguments")
    argument_list = []
    if arguments:
      for arg in arguments.children:
        if arg.type == "argument":
          argument_list.append(file_content[arg.start_byte:arg.end_byte].decode())
    extracts.append((function_name, argument_list, node.text, php_file))
  else:
    for child in node.children:
      extract_function_calls(php_file, child, extracts, file_content, name_match)

extract_function_calls(php_file, tree.root_node, asdf, file_content, "add_action")
```


# References
- Setup steps can be taken from [Python Tree-sitter](https://github.com/tree-sitter/py-tree-sitter).
- [Tree-sitter Python bindings](https://github.com/tree-sitter/py-tree-sitter)
- [Tree-sitter PHP grammar](https://github.com/tree-sitter/tree-sitter-php)


Cheers and hacky eastern