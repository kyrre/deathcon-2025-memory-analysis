import marimo

__generated_with = "0.16.1"
app = marimo.App(
    width="medium",
    app_title="YARA",
    css_file="",
    html_head_file="",
)

with app.setup(hide_code=True):
    import marimo as mo


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    <div align="center">
        <img src="public/yarax.png" style="max-width: 300px; margin-bottom: 0.5em;"/>
        <p style="
            font-size: 0.9em;
            font-weight: 600;
            margin: 0;
            font-family: system-ui, sans-serif;
        ">
          Interactive YARA development 
         </p>
    </div>

    Until now, we’ve been using marimo mainly to process and explore the output of Volatility plugins.  
    This is a great use-case, but marimo can do more than query data and create visualizations.  

    In this notebook, we’ll try something different. We’ll use marimo’s reactive features and UI components to build a custom environment for YARA development. This means you can write rules, test them against sample data, and refine them step by step, all inside the notebook.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    ## An interactive YARA editor
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    When looking at a VAD flagged as suspicious belonging to  `explorer.exe`, we found an embedded PE. This file contained imports and strings linked to keylogging activity. 

    For example, some of the extracted strings include the list below:

    ```plain
    [ESC]
    [LEFT]
    [RIGHT]
    [UP]
    [DOWN]
    [END]
    [HOME]
    [DELETE]
    [BACKSPACE]
    [INSERT]
    [CTRL]
    [ALT]
    ```
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Detecting the presence of these would be a good YARA rule. This gives us a chance to show how to 
    turn marimo into a development environment for YARA rules.


    To get started, we first import the `yara_x` package. Then we define a couple of simple rules as a string.

    If you are unfamiliar with YARA-X they have great tutorial on their [website](https://virustotal.github.io/yara-x/docs/intro/getting-started/).
    """
    )
    return


@app.cell
def _():
    import yara_x
    return (yara_x,)


@app.cell
def _():
    yara_rule = """
    rule keylogger_specialkey_a : Keylogger { 
        meta:
            description = "a keylogger rule 🐶"

        strings:
            $a1 = "[BACKSPACE]"
            $a2 = "[DELETE]"

        condition:
            2 of ($a*)
    }

    rule keylogger_specialkey_b : Keylogger {
        meta:
            description = "a keylogger rule"

        strings:
            $a1 = "[HOME]"
            $a2 = "[DELETE]"

        condition:
            2 of ($a*)
    }
    """
    return (yara_rule,)


@app.cell
def _():
    binary = open("output/pid.6616.vad.0x2480000-0x24adfff.dmp", mode="rb").read()
    return (binary,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    The YARA-X Python API makes it easy to compile rules and scan data in memory. You create a rule with yara_x.compile(), and then call rules.scan() on a byte sequence. The result contains the rules that matched, their patterns, and the match offsets. 

    In practice, using the API only takes a few lines. First compile the rule, then scan a byte sequence, and finally inspect the matches:
    """
    )
    return


@app.cell
def _(binary, yara_rule, yara_x):
    # use leading underscores to avoid global names!

    _rules = yara_x.compile(yara_rule)
    _result = _rules.scan(binary)

    for _rule in _result.matching_rules:
        for _pattern in _rule.patterns:
            for _hit in _pattern.matches:
                _off = _hit.offset
                _len = _hit.length
                print(f"{_rule.identifier}:{_pattern.identifier} @ {hex(_off)} len={_len}")
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""### Highlighting""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    We’ll reuse the same idea as our search highlighter: YARA gives us start and end offsets for every match. With those positions we can grab a small window of bytes around the hit and mark the exact region that matched.

    To keep things flexible, our helper takes a highlighter function. It receives the surrounding chunk, the match boundaries (start and end), and a mode ("hex" or "ascii"). From there it decides how to format the output - by default it highlights the match, but you can also swap in a simpler version that just slices the bytes.
    """
    )
    return


@app.cell
def _(yara_x):
    def yara_scan_with_context(binary: bytes, rule_text: str, context: int = 8, render_highlight=None):
        """
        Scan a binary with YARA-X and return matches with surrounding context.
        """

        # default "highligthing" - just extract the match as is
        if render_highlight is None:

            def render_highlight(chunk, hs, he, mode):
                return chunk[hs:he]

        rules = yara_x.compile(rule_text)
        result = rules.scan(binary)

        matches = []
        n = len(binary)

        for rule in result.matching_rules:
            for pat in rule.patterns:
                for m in pat.matches:
                    off, length = m.offset, m.length

                    pre = max(0, off - context)
                    post = min(n, off + length + context)

                    chunk = binary[pre:post]
                    hs = off - pre
                    he = off - pre + length

                    matches.append(
                        {
                            "rule": rule.identifier,
                            "pattern": pat.identifier,
                            "offset": off,
                            "length": length,
                            "bytes": render_highlight(chunk, hs, he, "hex"),
                            "ascii": render_highlight(chunk, hs, he, "ascii"),
                        }
                    )

        return matches
    return (yara_scan_with_context,)


@app.cell(hide_code=True)
def _():
    mo.md(r"""With the default "highlighting" functinon we get the following result.""")
    return


@app.cell
def _(binary, yara_rule, yara_scan_with_context):
    _matches = yara_scan_with_context(binary, yara_rule, context=8)
    _matches[0]
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Below are utility functions that prepare and highlight the bytes matched by a YARA rule.""")
    return


@app.cell
def _():
    def _to_ascii(b: bytes) -> str:
        """Convert bytes to printable ASCII; non-printables become '.'."""
        return "".join(chr(x) if 0x20 <= x <= 0x7E else "." for x in b)


    def _clamp_span(start: int, end: int, n: int) -> tuple[int, int]:
        """Clamp [start, end) to [0, n] and ensure end >= start."""
        start = max(0, min(start, n))
        end = max(start, min(end, n))
        return start, end


    def render_match(chunk: bytes, start: int, end: int, mode: str = "ascii") -> mo.Html:
        """
        Render a highlighted match from a byte chunk.

        start/end are byte indexes into the chunk, half-open [start, end).
        In hex view each byte renders as one token like "3f". In ascii view each byte renders
        as one character or '.'.
        """
        if mode == "hex":
            tokens = [f"{x:02x}" for x in chunk]
            start, end = _clamp_span(start, end, len(tokens))
            pre = " ".join(tokens[:start])
            hit = " ".join(tokens[start:end])
            post = " ".join(tokens[end:])
        elif mode == "ascii":
            s = _to_ascii(chunk)
            start, end = _clamp_span(start, end, len(s))
            pre, hit, post = s[:start], s[start:end], s[end:]
        else:
            raise ValueError("mode must be 'hex' or 'ascii'")

        return create_highlight_html(pre, hit, post)
    return (render_match,)


@app.cell(hide_code=True)
def _():
    mo.md(r"""The only function left to define is `create_highlight_html`, which is responsible for rendering the highlighted bytes.""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## Exercise 1

    Write a function `create_highlight_html` that builds a `mo.Html` object and applies the highlighting.
    """
    )
    return


@app.function
# def create_highlight_html(pre: str, hit: str, post: str) -> mo.Html:
#     """Return HTML with the hit wrapped for highlighting."""
#     return mo.Html(f"""
#         {pre}
#         <!-- wrap the hit here, e.g. with <mark> or <b> -->
#         {hit}
#         {post}
#     """)


def create_highlight_html(pre: str, hit: str, post: str) -> mo.Html:
    return mo.Html(f"""
    <span style='
        font-size: 0.85rem;
        line-height: 1.35;
        letter-spacing: 0.02em;
    '>
        {pre}
        <mark style="
            background-color: #ffe58f;
            color: #222;
            padding: 0 2px;
            border-radius: 2px;
            font-weight: 500;
            box-decoration-break: clone;
        ">{hit}</mark>
        {post}
    </span>""")


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Our version": mo.md("""
            ```python
              def create_highlight_html(pre: str, hit: str, post: str) -> mo.Html:
                 return mo.Html(f'''
                    <span style='
                        font-size: 0.85rem;
                        line-height: 1.35;
                        letter-spacing: 0.02em;
                    '>
                        {pre}
                        <mark style="
                            background-color: #ffe58f;
                            color: #222;
                            padding: 0 2px;
                            border-radius: 2px;
                            font-weight: 500;
                            box-decoration-break: clone;
                        ">{hit}</mark>
                        {post}
                    </span>
                '''')

            ```
            """)
        }
    )
    return


@app.cell
def _(binary, render_match, yara_rule, yara_scan_with_context):
    matches = yara_scan_with_context(binary, yara_rule, render_highlight=render_match, context=8)

    matches[0]
    return (matches,)


@app.cell(hide_code=True)
def _():
    mo.md(r"""When we put everything together and use the table widget it looks like this:""")
    return


@app.cell
def _(matches):
    def show_matches(matches):
        """Render YARA matches in a marimo table."""

        def format_hex_addr(addr: int | None) -> str | None:
            return f"0x{addr:x}" if addr is not None else None

        return mo.ui.table(
            matches,
            wrapped_columns=["bytes", "ascii"],
            format_mapping={"offset": format_hex_addr},
            selection=None,
            show_column_summaries=False,
            show_data_types=False,
            show_download=False,
            page_size=20,
        )


    show_matches(matches)
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ### Interactive YARA rule editor

    We have the pieces to run rules, edit rules, and render highlights. Let’s put them together into a small editor with live preview.  You write a rule. The preview shows matches as you type.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""The first component we need for this is the code editor - [mo.ui.code_editor](https://docs.marimo.io/api/inputs/code_editor/).""")
    return


@app.cell
def _():
    _editor = mo.ui.code_editor(
        value="""
    rule ExampleRule {
        strings:
            $a = "test"
        condition:
            $a
    }
    """,
        min_height=200,
        label="YARA rule editor",
        show_copy_button=True,
    )

    _editor
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""If you try to specify the language to be YARA, you will notice that it's not supported, but we won't let that deter us.""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## Exercise 2

    Build a small YARA editor with a preview table of matches.  
    Place them side by side, and make sure the table updates when the rule changes.

    *Hint:* wrap the scan in a `try/except`.  
    As you type, invalid rules will raise errors. Catch them and show the message to keep the editor usable.

    *Alternative:* instead of catching errors, you could gate evaluation behind a run button.  
    See the [state docs](https://docs.marimo.io/api/state/) if you want to store the last valid result.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Our version": mo.md("""

            In the first cell:
            ```python
            yara_editor = mo.ui.code_editor(value=yara_rule, min_height=400) 
            ```

            and in the second cell:

            ```python
            try:
                table = show_matches(yara_scan_with_context(binary, yara_editor.value))
            except Exception as e:
                error_message = str(e)
                table = mo.Html(f"<pre>{error_message}</pre>")

            mo.stack(
                [yara_editor, table],
                gap=1,
                justify="start"
            )
            ```

            """)
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ### Testing our rules

    So far we’ve built a way to *visualize YARA matches* interactively.   The next step is to make this part of a *rule development workflow*.

    marimo has built-in support for *pytest*.  If `pytest` is installed, any cell that defines only test functions

    ```python
    def test_example():
        assert 1 == 1
    ```

    or test classes 

    ```python 
    class Test...
    ``` 

    will run as unit tests.

    This lets us write regression tests for our YARA rules right inside the notebook:

    - Check that a rule still matches the samples it was designed for.
    - Confirm it ignores unrelated content (low false positives).
    - Refine the logic until all tests pass.

    In short: we can develop and test YARA rules interactively without leaving marimo.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Let’s start with a simple example to show how this works.  

    We’ll define a function that stands in for some logic or computation.  
    Call it `my_function`.
    """
    )
    return


@app.function
def my_function():
    return 5


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    In a new cell we define a function whose name begins with `test_`.  
    pytest will pick it up automatically, and marimo will run it in place.

    If you’re not familiar with pytest, all you need to know is that a test is just an *assertion*.  
    If the condition is true, it passes.  
    If not, it fails.

    Here we check that `my_function()` returns `1`.
    """
    )
    return


@app.function
def test_something():
    assert 1 == my_function()


@app.cell(hide_code=True)
def _():
    mo.md(r"""The test will fail at first.  Try changing the definition of `my_function` until the test passes.  That way you can see how pytest and marimo work together in real time.""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Let’s take the same idea and apply it to YARA.  The aim is an interactive environment for rule development.

    We’ll keep a set of test files:

    - *true positives* the rule should match  
    - *true negatives* the rule should ignore  

    Each time the rule changes, run it against all tests.  
    If everything passes, the rule is stable.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Let’s build a small test suite for our YARA rules.  
    We’ll start with a true positive sample, then add cases that should fail or pass in specific ways.

    In practice you might keep a collection of samples in a folder or a database.

    Tests can be written in different styles:

    - check that certain files are always detected (true positives)  
    - check that clean files are never detected (true negatives)  
    - enforce thresholds, like “false positives must stay below X%”

    The setup can get more complex, but the core idea is the same:  define expectations and run the rule against them.
    """
    )
    return


@app.cell
def _():
    samples = [
        {
            "name": "true positive",
            "expected_matching_rules": ["keylogger_specialkey_a", "keylogger_specialkey_b"],
            "data": open("output/pid.6616.vad.0x2480000-0x24adfff.dmp", mode="rb").read(),
        },
        {"name": "just string", "expected_matching_rules": [], "data": b"nothing to see here"},
        {
            "name": "backspace_delete",  # should match keylogger_specialkey_a only
            "expected_matching_rules": ["keylogger_specialkey_a"],
            "data": b"...random... [BACKSPACE] ... some bytes ... [DELETE] ...",
        },
        {
            "name": "home_delete",  # should match keylogger_specialkey_b only
            "expected_matching_rules": ["keylogger_specialkey_b"],
            "data": b"prefix [HOME] blah blah [DELETE] suffix",
        },
        {
            "name": "both_rules",  # has BACKSPACE + DELETE + HOME => both rules match
            "expected_matching_rules": ["keylogger_specialkey_a", "keylogger_specialkey_b"],
            "data": b"[HOME] noise [DELETE] more noise [BACKSPACE] end",
        },
        {
            "name": "only_home",  # only [HOME] -> no match
            "expected_matching_rules": [],
            "data": b"some text [HOME] more text",
        },
        {
            "name": "only_delete",  # only [DELETE] -> no match
            "expected_matching_rules": [],
            "data": b"garbage [DELETE] garbage",
        },
        {
            "name": "home_backspace_no_delete",  # neither rule gets its full 2-of-2
            "expected_matching_rules": [],
            "data": b"stuff [HOME] ... [BACKSPACE] ...",
        },
        {
            "name": "multiple_hits_bamboo",  # both tokens for keylogger_specialkey_a, repeated
            "expected_matching_rules": ["keylogger_specialkey_a"],
            "data": b"[BACKSPACE] aaa [DELETE] bbb [BACKSPACE] ccc [DELETE]",
        },
        {
            "name": "spaced_out_tokens",  # large gap/noise shouldn’t matter
            "expected_matching_rules": ["keylogger_specialkey_b"],
            "data": b"[HOME]" + b"x" * 4096 + b"[DELETE]",
        },
        {
            "name": "brackets_but_not_tokens",  # similar-looking strings that shouldn't match
            "expected_matching_rules": [],
            "data": b"[H0ME] [DEL ETE] [BACKSPACE ]",  # note typos/spaces
        },
    ]
    return (samples,)


@app.cell
def _():
    import pytest
    return (pytest,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    The setup is simple.  
    We keep a set of rules and a list of samples. Each sample says which rules should match.  

    With `pytest.mark.parametrize`, we can run the same test across all samples. For each one, the test scans the bytes, collects the rule names that matched, and compares them to the expected set.  

    If the sets don’t match, the test fails.  
    This gives us clear, focused tests without wrapping everything into one big check.
    """
    )
    return


@app.cell
def _(binary, yara_rule, yara_x):
    rules = yara_x.compile(yara_rule)
    result = rules.scan(binary)
    return (rules,)


@app.cell
def _(pytest, rules, samples):
    @pytest.mark.parametrize(
        "sample",
        samples,
        ids=[s["name"] for s in samples],
    )
    def test_yara_matches(sample, rules=rules):
        result = rules.scan(sample["data"])
        expected = set(sample["expected_matching_rules"])
        actual = {r.identifier for r in result.matching_rules}

        missing = expected - actual
        unexpected = actual - expected
        assert not missing and not unexpected, f"Missing: {sorted(missing)} | Unexpected: {sorted(unexpected)}"
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    We won’t cover PyTest in detail here. If you want to learn more, CalmCode has some good resources.

    This wraps up our example of building a basic interactive environment for YARA development in marimo.

    For extra practice, try building a full dashboard app:

    - add a code editor
    - show test results in another tab
    - let the user pick which sample to scan

    You can also connect the editor to the filesystem so you can edit and reload rules from disk instead of keeping them only in notebook state.

    That’s the end of this section.
    """
    )
    return




if __name__ == "__main__":
    app.run()
