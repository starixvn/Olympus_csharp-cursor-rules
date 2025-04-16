import html
import re
# Write function to read file csharp-rules.txt
# and split it into a list of rules
# this file contains many rules, each rule is separated by a line with format Rule csharpsquid:Sxxxxx
# xxxxx is a number, and the rule is in the next line
def read_rules(file_path):
    rules = []
    # This file encoding is UTF-8, so we need to specify it when opening the file
    # Also, we need to remove the BOM (Byte Order Mark) if present
    # to do this we can use the codecs module
    import codecs
    with codecs.open(file_path, 'r', encoding='utf-8-sig') as file:    
        lines = file.readlines()
        rule_id = ''
        rule_description = ''
        for i in range(len(lines)):
            if lines[i].startswith('Rule csharpsquid:S'):
                new_rule_id = extract_rule_id(lines[i])
                if rule_id and rule_description:
                    rules.append((rule_id, rule_description))                
                    rule_description = ''
                rule_id = new_rule_id
            else:
                rule_description += lines[i].strip() + '\n'
        if rule_id and rule_description:
            rules.append((rule_id, rule_description))
    return rules

# Write a function to extract rule id from text. Example extract S1698 from this text "Rule csharpsquid:S1698"
def extract_rule_id(text):
    import re
    match = re.search(r'Rule csharpsquid:(S\d+)', text)
    if match:
        return match.group(1)
    return None

# this is a sample of a rule:

# <h2>Why is this an issue?</h2>
# <p>Using the equality <code>==</code> and inequality <code>!=</code> operators to compare two objects generally works. The operators can be
# overloaded, and therefore the comparison can resolve to the appropriate method. However, when the operators are used on interface instances, then
# <code>==</code> resolves to reference equality, which may result in unexpected behavior if implementing classes override <code>Equals</code>.
# Similarly, when a class overrides <code>Equals</code>, but instances are compared with non-overloaded <code>==</code>, there is a high chance that
# value comparison was meant instead of the reference one.</p>
# <h3>Noncompliant code example</h3>
# <pre>
# public interface IMyInterface
# {
# }

# public class MyClass : IMyInterface
# {
#     public override bool Equals(object obj)
#     {
#         //...
#     }
# }

# public class Program
# {
#     public static void Method(IMyInterface instance1, IMyInterface instance2)
#     {
#         if (instance1 == instance2) // Noncompliant, will do reference equality check, but was that intended? MyClass overrides Equals.
#         {
#             Console.WriteLine("Equal");
#         }
#     }
# }
# </pre>
# <h3>Compliant solution</h3>
# <pre>
# public interface IMyInterface
# {
# }

# public class MyClass : IMyInterface
# {
#     public override bool Equals(object obj)
#     {
#         //...
#     }
# }

# public class Program
# {
#     public static void Method(IMyInterface instance1, IMyInterface instance2)
#     {
#         if (object.Equals(instance1, instance2)) // object.Equals checks for null and then calls the instance based Equals, so MyClass.Equals
#         {
#             Console.WriteLine("Equal");
#         }
#     }
# }
# </pre>
# <h3>Exceptions</h3>
# <p>The rule does not report on comparisons of <code>System.Type</code> instances and on comparisons inside <code>Equals</code> overrides.</p>
# <p>It also does not raise an issue when one of the operands is <code>null</code> nor when one of the operand is cast to <code>object</code> (because
# in this case we want to ensure reference equality even if some <code>==</code> overload is present).</p>
# <h2>Resources</h2>
# <ul>
#   <li> <a href="https://cwe.mitre.org/data/definitions/595">MITRE, CWE-595</a> - Comparison of Object References Instead of Object Contents </li>
#   <li> <a href="https://cwe.mitre.org/data/definitions/597">MITRE, CWE-597</a> - Use of Wrong Operator in String Comparison </li>
# </ul>

# Write a function to extract the rule id and description from the file
# and return a list of tuples, each tuple contains the rule id, short description and full description
# the short description is the text between the first <p> and </p> tags
# and the full description is the text after the short description
# Note: 
#   - The text from <h2>Resources</h2> to the end should be removed from the description
#   - The text from <h3>Documentation</h3> to the end should be removed from the description
#   - The text should be cleaned from html tags, and the text should be converted to plain text

def extract_rule_info(rules):
    import re
    rule_info = []
    for rule in rules:
        rule_id, rule_description = rule
        # Extract the short description
        short_description = re.search(r'<p>(.*?)</p>', rule_description, re.DOTALL)
        if short_description:
            short_description = short_description.group(1).strip()
        else:
            short_description = ''
        
        # Extract the full description        
        full_description = re.sub(r'<h2>Resources</h2>.*', '', rule_description, flags=re.DOTALL)
        full_description = re.sub(r'<h3>Documentation</h3>.*', '', full_description, flags=re.DOTALL)
        # Remove the text from the beginning to the the first </p> tag
        full_description = get_full_description(full_description)
        
        # Remove html tags
        short_description = html_to_plain_text(short_description)
        full_description = html_to_plain_text(full_description)

        # Insert new line after each </pre> tag
        full_description = re.sub(r'</pre>', '</pre>\n', full_description)
        short_description = re.sub(r'</pre>', '</pre>\n', short_description)
        # Replace &gt; with >, &lt; with <, &amp; with &, and &nbsp; with space
        short_description = short_description.replace('&gt;', '>').replace('&lt;', '<').replace('&amp;', '&').replace('&nbsp;', ' ')
        full_description = full_description.replace('&gt;', '>').replace('&lt;', '<').replace('&amp;', '&').replace('&nbsp;', ' ')
        
        # Trim whitespace at the beginning and end of the string
        short_description = short_description.strip()   
        full_description = full_description.strip()
                
        rule_info.append((rule_id, short_description, full_description))
           
    return rule_info

def get_full_description(text):
    """
    Removes text from the beginning of the input string up to and including the first
    </p> tag.

    Args:
        text: The input string containing HTML-like text.

    Returns:
        The modified string with the initial portion removed.
    """

    match = re.search(r'</p>', text)  # Find the first closing </p> tag
    if match:
        end_index = match.end()  # Get the index after the closing tag
        return text[end_index:]
    else:
        return text  # Return the original text if no closing </p> tag is found


# Write a function to convert html to plain text
def html_to_plain_text(html_string):
    """
    Converts an HTML string to plain text, preserving content within <pre> tags.

    This function removes HTML tags, decodes HTML entities, and normalizes whitespace
    to produce a clean, readable text representation of the input HTML,
    while keeping the text inside <pre> and </pre> tags intact.

    Args:
        html_string: The HTML string to convert.

    Returns:
        The plain text representation of the HTML.
    """

    def replace_with_placeholder(match):
        """Helper function to replace matched <pre>...</pre> blocks with placeholders."""
        placeholder = f"__PRE_START_{len(pre_blocks)}__"
        pre_blocks.append(match.group(0))  # Store the entire <pre>...</pre> block
        return placeholder

    pre_blocks = []
    # 1.  Extract and replace <pre> blocks with placeholders
    text = re.sub(r'<pre.*?</pre>', replace_with_placeholder, html_string, flags=re.S | re.I)

    # 2. Remove other HTML tags
    text = re.sub(r'<[^>]*?>', '', text)

    # 3. Decode HTML entities
    text = html.unescape(text)

    # 4. Normalize whitespace (outside of <pre> content)
    text = re.sub(r'\s+', ' ', text).strip()

    # 5.  Restore <pre> blocks
    def replace_placeholder_with_pre(match):
        """Helper function to restore the <pre>...</pre> blocks."""
        index = int(match.group(1))
        return pre_blocks[index]

    text = re.sub(r'__PRE_START_(\d+?)__', replace_placeholder_with_pre, text)

    return text

# Write a function to read the file ruleids.txt and return a list of rule ids
def read_rule_ids(file_path):
    rule_ids = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            rule_id = line.strip()
            rule_ids.append(rule_id)
    return rule_ids

rules = read_rules('csharp-rules.txt')
ruleids = read_rule_ids('ruleids.txt')
rule_info = extract_rule_info(rules)
for rule in rule_info:
    # write to file {rule[0]}.mdc the following content:
    #---
#description: short description
#globs:
#  - "**/*.cs"
#alwaysApply: true
#---
## Rule content
#
# full description

    rule_id, short_description, full_description = rule
    
    if rule_id not in ruleids:
        continue
    
    file_name = f".cursor/rules/{rule_id}.mdc"    
    # Write file with encoding utf-8 and BOM
    
    with open(file_name, 'w', encoding='utf-8-sig') as file:
        file.write(f"---\n")
        file.write(f"description: {short_description}\n")
        file.write(f"globs:\n")
        file.write(f"  - '**/*.cs'\n")
        file.write(f"alwaysApply: true\n")
        file.write(f"---\n")
        file.write(f"# Rule content\n")
        file.write(f"\n")
        file.write(f"{full_description}\n")
        
        