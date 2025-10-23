import marimo

__generated_with = "0.16.0"
app = marimo.App(width="medium", app_title="Strings", css_file="")

with app.setup(hide_code=True):
    import ibis
    import ibis.selectors as s
    import marimo as mo

    from ibis import _


    def get_default_connection():
        import duckdb

        return ibis.duckdb.from_connection(duckdb)


    con = get_default_connection()
    ibis.options.interactive = True


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    <div style="
        display: flex;
        flex-direction: column;
        align-items: center;
        margin: 3em 0;
    ">
      <h1 style="
          font-family: 'Montserrat', 'Inter', ui-sans-serif, system-ui, -apple-system, Helvetica, Arial, sans-serif;
          font-size: 3rem;
          font-weight: 800;
          color: #111;
          margin: 0;
          line-height: 1.1;
      ">
        <span style="font-size: 2.4rem; color:#666; font-weight: 300; margin-right: -0.15em;">„</span>
        <span style="font-weight: 800;">Strings</span>
        <span style="font-size: 2.4rem; color:#666; font-weight: 300; margin-left: -0.15em;">“</span>
      </h1>
      <p style="
          font-size: 1rem;
          font-weight: 400;
          margin-top: 0.8em;
          font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, Helvetica, Arial, sans-serif;
          letter-spacing: 0.01em;
          color: #444;
      ">
        Creating tools for textual data
      </p>
    </div>

    The previous notebook ended with a triage dashboard. Sometimes a plugin will highlight suspicious activity right away, but that is not always the case. Usually, no single plugin will reveal the malicious activity. Many important clues show up only as plain text in memory. String analysis helps expose a wide range of crucial information in memory, such as suspicious file names, IP addresses, URLs, Windows API calls, and even attacker commands. Malicious software, during execution, leaves behind readable strings related to its operation, like injected DLL names, attacker-controlled domains, encryption keys, or code fragments, directly in RAM. Also, every string thas was ever present on the screen must have been present in clear text in memory at one point. These leads can immediately help us direct our attention to the relevant memory regions, even if the binary is obfuscated or packed.

    Working with raw strings can be overwhelming, since a dump will contain millions of them. The goal here is to make that manageable. We will look at different ways of extracting strings, normalize them into a structure we can query, and apply simple filters and enrichments. We will also add search features, so we can focus on patterns like URLs, emails, or file paths instead of scrolling through endless output.

    In short, this notebook is about turning a noisy collection of strings into something we can explore and reason about efficiently.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""In the dashboard we saw two processes with suspicious threads. We will use those as our starting point. By pivoting on them, we can focus the string search and avoid getting lost in the noise of the full dump.""")
    return


@app.function
def format_hex_addr(addr):
    """Format integer address as hex string"""
    return f"0x{addr:016x}" if addr is not None else None


@app.cell
def _():
    suspicious_threads = con.read_parquet(
        "volatility_plugin_output/windows.malware.suspicious_threads.SuspiciousThreads.parquet"
    ).rename("snake_case")

    mo.ui.table(
        suspicious_threads,
        format_mapping={"address": format_hex_addr},
        selection=None,
        show_column_summaries=False,
    )
    return (suspicious_threads,)


@app.cell(hide_code=True)
def _():
    mo.md(r"""Using this as our starting point, we can now look at the VADs that are marked as suspicious.""")
    return


@app.cell
def _():
    vads = con.read_parquet("volatility_plugin_output/windows.vadinfo.VadInfo.parquet").rename("snake_case")

    mo.ui.table(
        vads,
        format_mapping={
            "offset": format_hex_addr,
            "start_vpn": format_hex_addr,
            "end_vpn": format_hex_addr,
            "parent": format_hex_addr,
        },
        selection=None,
        show_column_summaries=False,
    )
    return (vads,)


@app.cell(hide_code=True)
def _():
    mo.md(r"""The `file_output` column shows where the memory content is written locally. This is the file we will read when extracting strings.""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    To actually extract the strings from these memory dumps, we can re-use some functions from the [flare-floss](https://github.com/mandiant/flare-floss) package. FLOSS is a sophisticated string-extraction library that goes beyond simple ASCII/Unicode scanning. It can automatically

    - deobfuscate stack strings  
    - decode common encodings  
    - recover dynamically constructed values by emulating relevant code paths [[ref](https://cloud.google.com/blog/topics/threat-intelligence/automatically-extracting-obfuscated-strings/)]  

    In our case, though, we’re working with *live memory dumps*. That means most of the malware’s strings should already be present in their unobfuscated form at runtime. Instead of forcing FLOSS to emulate every possible decoding routine, we can rely on the fact that execution has already happened and simply scan for the plain strings that have been materialized in memory.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Now we’ll extract strings from the VADs flagged as suspicious. We’ll read each file from file_output and pull ASCII and Unicode strings using FLOSS.""")
    return


@app.cell
def _(suspicious_threads, vads):
    suspicious_vads = suspicious_threads.join(
        vads,
        [
            vads.start_vpn <= suspicious_threads.address,
            suspicious_threads.address <= vads.end_vpn,
            vads.pid == suspicious_threads.pid,
        ],
    )
    return (suspicious_vads,)


@app.cell
def _(suspicious_files):
    suspicious_files
    return


@app.function
def to_list(t):
    return t.to_pyarrow().to_pylist()


@app.cell
def _(suspicious_vads):
    suspicious_files = to_list(suspicious_vads.distinct(on=["file_output"]).file_output)

    suspicious_files
    return (suspicious_files,)


@app.cell
def _():
    import os
    from floss.strings import extract_ascii_strings, extract_unicode_strings


    def extract_strings_from_vad(filename, string_type="ascii", min_length=3):
        file_path = f"output/{filename}"
        if not os.path.exists(file_path):
            return ""

        with open(file_path, "rb") as fh:
            data = fh.read()

        if string_type == "ascii":
            extracted = extract_ascii_strings(data, min_length)
        else:
            extracted = extract_unicode_strings(data, min_length)

        return " ".join(item.string for item in extracted)
    return (extract_strings_from_vad,)


@app.cell
def _(extract_strings_from_vad):
    extract_strings_from_vad("pid.6616.vad.0x2480000-0x24adfff.dmp", "unicode")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    This helper reads the memory dump for a given VAD and extracts strings from it. We can choose between ASCII or Unicode mode, and set a minimum length to avoid noise.

    With this function in place we can extract both ASCII and Unicode strings. Next we’ll run it across all the VAD files and load the results back into Ibis and DuckDB for analysis.
    """
    )
    return


@app.cell
def _(extract_strings_from_vad, suspicious_files):
    import uuid


    def create_strings_table(con, files, table_name="strings"):
        rows = [
            {
                "id": str(uuid.uuid4()),
                "filename": filename,
                "ascii": extract_strings_from_vad(filename),
                "unicode": extract_strings_from_vad(filename, string_type="unicode"),
            }
            for filename in files
        ]

        return con.create_table(table_name, rows, overwrite=True)


    strings_from_suspicious_vads = create_strings_table(con, suspicious_files)
    return create_strings_table, strings_from_suspicious_vads


@app.cell(hide_code=True)
def _():
    mo.md(r"""We now build a strings table in DuckDB. Each row represents one VAD dump. We give it a unique ID, keep track of the filename, and store both ASCII and Unicode strings extracted with our helper.""")
    return


@app.cell
def _(strings_from_suspicious_vads):
    strings_from_suspicious_vads
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    For now we keep one text field per VAD. At a later point we can reshape it so that each string gets its own row.  

    This can be done in two steps:

    1. `split` the string column  
    2. `unnest` the resulting array  

    The example below does this for the ASCII column.
    """
    )
    return


@app.cell
def _(strings_from_suspicious_vads):
    (
        strings_from_suspicious_vads.mutate(ascii=_.ascii.split(" ").unnest())
        .filter(_.ascii.length() >= 5)
        .distinct(on=["ascii"])
        .drop(_.unicode)
    )
    return


@app.cell
def _():
    @ibis.udf.scalar.builtin
    def regexp_extract_all(s: str, pattern: str, group: int = 0) -> list[str]: ...


    def extract_pattern(col, pattern):
        """Helper function to extract all matches for a given pattern."""
        return regexp_extract_all(col, pattern, 0)


    def urls(col):
        """
        Extract URLs from the given column.

        A URL starts with either http or ftp and followed by non-whitespace characters.
        """
        pattern = (
            r"(?i)\b(?:https?|ftp)://"  # Start with http or ftp (case insensitive)
            r"\S+"  # Followed by non-whitespace characters
        )
        return extract_pattern(col, pattern)


    def emails(col):
        """
        Extract email addresses from the given column.

        An email address consists of characters allowed in the user part followed by an '@' sign, domain name, and top-level domain.
        """
        pattern = (
            r"[A-Za-z0-9._%+\-]+"  # User part
            r"@[A-Za-z0-9.\-]+"  # '@' sign and domain name
            r"\.[A-Za-z]{2,}"  # Top-level domain
        )
        return extract_pattern(col, pattern)


    def ipv4s(col):
        """
        Extract IPv4 addresses from the given column.

        An IPv4 address consists of four octets separated by dots.
        """
        pattern = (
            r"\b(?:\d{1,3}\.){3}"  # Three octets followed by dots
            r"\d{1,3}\b"  # Fourth octet
        )
        return extract_pattern(col, pattern)


    def win_paths(col):
        """
        Extract Windows file paths from the given column.

        A Windows file path may start with a drive letter followed by backslashes or a UNC path.
        """
        pattern = (
            r"[A-Za-z]:"  # Drive letter
            r"(?:\\[^\s\\/:\*\?\"<>\|]+)+\\?"  # Path components
            r"|\\\\[^\s\\/:\*\?\"<>\|]+"  # UNC path
            r"(?:\\[^\s\\/:\*\?\"<>\|]+)+"  # Path components
        )
        return extract_pattern(col, pattern)


    def file_exts(col):
        """
        Extract file extensions from the given column.

        A file extension starts with a dot followed by 1 to 6 alphanumeric characters.
        """
        pattern = r"\.[A-Za-z0-9]{1,6}\b"  # Dot followed by 1 to 6 alphanumeric characters
        return extract_pattern(col, pattern)


    def exe_dlls(col):
        """
        Extract executable and DLL files from the given column.

        These files have extensions like exe, dll, sys, and ocx.
        """
        pattern = (
            r"\b(?:[A-Za-z0-9_\-]+)"  # File name part
            r"\.(?:exe|dll|sys|ocx)\b"  # Extensions
        )
        return extract_pattern(col, pattern)


    def doc_scripts(col):
        """
        Extract document and script files from the given column.

        These files have extensions like docm, xlsm, pptm, vbs, js, ps1, bat, and cmd.
        """
        pattern = (
            r"\b(?:[A-Za-z0-9_\-]+)"  # File name part
            r"\.(?:docm?|xlsm?|pptm?"  # Document extensions
            r"|vbs|js|ps1|bat|cmd)\b"  # Script extensions
        )
        return extract_pattern(col, pattern)


    def archives(col):
        """
        Extract archive files from the given column.

        These files have extensions like zip, rar, 7z, gz, bz2, xz, and tar.
        """
        pattern = (
            r"\b(?:[A-Za-z0-9_\-]+)"  # File name part
            r"\.(?:zip|rar|7z|gz|bz2|xz|tar)\b"  # Archive extensions
        )
        return extract_pattern(col, pattern)
    return (
        archives,
        doc_scripts,
        emails,
        exe_dlls,
        file_exts,
        ipv4s,
        urls,
        win_paths,
    )


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    With these helpers defined we can enrich our strings table. For each VAD we add new columns for URLs, emails, IPs, file paths, and common file types. 


    We then filter the table so that only rows with at least one match remain.  This leaves us with a smaller set of strings that are more likely to be relevant.
    """
    )
    return


@app.cell
def _(
    archives,
    doc_scripts,
    emails,
    exe_dlls,
    file_exts,
    ipv4s,
    strings_from_suspicious_vads,
    urls,
    win_paths,
):
    def extract_patterns_from_strings(suspicious_strings_df, pattern_extractors):
        # Initialize any_patterns_found condition
        any_patterns_found = ibis.literal(False)

        # Initialize columns for selection
        columns = {
            "filename": _.filename,
            "ascii": _.ascii,
        }

        # Build selection columns and OR condition
        for name, fn in pattern_extractors.items():
            columns[name] = fn(_.ascii)
            any_patterns_found |= columns[name].length() > 0

        # Select relevant columns, filter rows, and drop the ascii column
        extracted_strings = suspicious_strings_df.select(**columns).filter(any_patterns_found).drop(_.ascii)

        # Final result
        return extracted_strings


    # Extractor name → function
    PATTERN_EXTRACTORS = {
        "urls": urls,
        "emails": emails,
        "ipv4s": ipv4s,
        "win_paths": win_paths,
        "file_exts": file_exts,
        "exe_dlls": exe_dlls,
        "doc_scripts": doc_scripts,
        "archives": archives,
    }

    # Apply the function to `strings_from_suspicious_vads`
    extracted_strings = extract_patterns_from_strings(strings_from_suspicious_vads, PATTERN_EXTRACTORS)
    return PATTERN_EXTRACTORS, extract_patterns_from_strings, extracted_strings


@app.cell
def _(extracted_strings):
    extracted_strings
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""We can create a small data-app to make the process more seamless.""")
    return


@app.cell
def _(PATTERN_EXTRACTORS):
    _options = list(PATTERN_EXTRACTORS.keys())
    selection = mo.ui.dropdown(
        _options,
        allow_select_none=False,
        value=_options[5],
        searchable=True,
    )

    min_len = mo.ui.slider(start=1, stop=20, step=1, value=8, show_value=True)
    return min_len, selection


@app.function
def create_table(extracted_strings, selection, min_len):
    # selected content (unnested strings)
    content = extracted_strings[selection.value].unnest()

    # build the table expression
    _result_expr = extracted_strings.select(_.filename, content=content).filter(_.content.length() >= min_len.value)

    # materialize as polars dataframe to speed up pagination
    _df = _result_expr.to_polars()

    # table component
    _table = mo.ui.table(
        _df,
        selection=None,
        show_download=False,
        show_column_summaries=False,
        page_size=10,
    )

    return _table


@app.function
def render_strings_overview(extracted_strings, selection, min_len):
    container = mo.md(f"""
    <div style="display:flex; flex-direction:column; gap:10px; align-items:stretch; min-width:500px; max-width:fit-content;">
      <div style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
        {selection}
        <div style="display:flex; align-items:center; gap:8px;">
          {min_len} 
        </div>

      </div>
      <div style="width: 600px; min-height: 400px;">
          {create_table(extracted_strings, selection, min_len)}
      </div>
    </div>
    """)

    return container


@app.cell
def _(extracted_strings, min_len, selection):
    render_strings_overview(extracted_strings, selection, min_len)
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Lets run in on all the VADs from these processes.""")
    return


@app.cell
def _(vads):
    _explorer_onedrive_vads = vads.filter((_.process == "explorer.exe") | (_.process == "OneDrive.exe"))
    files = to_list(_explorer_onedrive_vads.file_output)
    return (files,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Extracting strings can be slow, so we want to guard this code and only run it when the user clicks a button.
    We do that by checking `mo.stop(not run_button.value)`.
    This way, the heavy extraction only happens once per button press, instead of every time an ancestor cell changes.

    You can read more about handling expensive cells in the [documentation](https://docs.marimo.io/guides/expensive_notebooks/).
    """
    )
    return


@app.cell
def _():
    run_button = mo.ui.run_button(kind="info")
    run_button
    return (run_button,)


@app.cell
def _(
    PATTERN_EXTRACTORS,
    create_strings_table,
    extract_patterns_from_strings,
    files,
    run_button,
):
    mo.stop(not run_button.value)

    strings_from_all_vads = create_strings_table(con, files, table_name="all_vad_strings")
    all_extracted_strings = extract_patterns_from_strings(strings_from_all_vads, PATTERN_EXTRACTORS)
    return (all_extracted_strings,)


@app.cell
def _(all_extracted_strings, min_len, selection):
    render_strings_overview(all_extracted_strings, selection, min_len)
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## Exercise 1

    Build a small viewer to browse Unicode and ASCII strings side by side.
    Include one length control for ASCII and one for Unicode.

    See the image below for reference.

    ![](public/image.png)
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## String utilities

    We don’t always need dataframes or DuckDB.
    Sometimes it’s simpler to use plain Python structures like lists, sets, and dictionaries.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    As an example, let’s work with the URLs we found.

    - `tldextract` splits a URL into subdomain, domain, and suffix.
    - `tranco` provides a ranking of the most common domains on the internet.

    Together these let us extract host names and then filter out the top domains.
    """
    )
    return


@app.cell
def _():
    import tldextract
    from tranco import Tranco
    return Tranco, tldextract


@app.cell
def _(Tranco):
    # Initialize Tranco (with caching)
    t = Tranco(cache=True, cache_dir=".tranco")
    latest = t.list()  # fetch the latest list
    return (latest,)


@app.cell
def _(latest):
    latest.top(10)
    return


@app.cell
def _(latest):
    top100 = set(latest.top(100))
    return (top100,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Now let’s pull out the URL column and collect only the unique values.
    We’ll drop empty entries and turn the result into a plain Python list of strings.
    """
    )
    return


@app.cell
def _(all_extracted_strings):
    _urls = all_extracted_strings.filter(_.urls.length() > 0).select(_.urls.unnest()).distinct()
    url_list = to_list(_urls.urls)
    return (url_list,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    To put this together, we can write a helper function.
    It will take a URL, extract its parts with `tldextract`, and then check with `tranco` whether the registered domain is in the top-100 list.
    """
    )
    return


@app.cell
def _(tldextract, top100):
    def extract_and_check_tranco(url: str) -> dict:
        """
        Extract URL components and check if the registered domain is in Tranco's top 100.
        """
        if not url:
            return {"subdomain": None, "domain": None, "suffix": None, "registered_domain": None, "is_tranco_top100": False}

        extracted = tldextract.extract(url)
        reg_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else None

        return {
            "url": url,
            "subdomain": extracted.subdomain or None,
            "domain": extracted.domain or None,
            "suffix": extracted.suffix or None,
            "registered_domain": reg_domain,
            "is_tranco_top100": (reg_domain in top100) if reg_domain else False,
        }
    return (extract_and_check_tranco,)


@app.cell(hide_code=True)
def _():
    mo.md(r"""For a single URL we get:""")
    return


@app.cell
def _(extract_and_check_tranco, url_list):
    extract_and_check_tranco(url_list[10])
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Now let’s apply this function to all our URLs.
    We’ll collect the results into an in-memory table and display it with a marimo table widget so we can explore the data.
    """
    )
    return


@app.cell
def _(extract_and_check_tranco, url_list):
    _t = [extract_and_check_tranco(_url) for _url in url_list]
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## Exercise 2

    Use the table above to spot a domain that looks suspicious. 

    If you have time, take it a step further: check whether this domain appears anywhere else in the memory dump.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""## Highlighting""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    VAD.
    The idea is simple: add a search bar where you type a word or pattern, and the tool highlights every match in the dump.

    This gives you quick context around each hit without having to scroll through raw text.
    It’s a lightweight way to spot suspicious strings and check how they appear inside memory.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    First, we’ll write a small helper that highlights matches in a string.
    It finds the search term and returns HTML with each match wrapped in `<mark>`
    tags so we get the 
    <mark style="background-color:#b9f6ca;">highlight</mark> effect.
    """
    )
    return


@app.cell
def _():
    import re
    import html


    def highlight_text(text, search_term):
        text = html.escape(text)
        if search_term.strip() == "":
            highlighted = text
        else:
            pattern = re.compile(re.escape(search_term), re.IGNORECASE)

            highlighted = pattern.sub(
                lambda m: f"""
                    <mark 
                        style='
                            background-color:#b9f6ca;
                            color: #222; 
                            padding: 0 2px; 
                            border-radius: 2px; 
                            font-weight: 500;'
                    >
                        {m.group(0)}
                    </mark>
                """,
                text,
            )

        return f"""
            <div
                style='
                    font-family: Arial, sans-serif;
                    font-size: 0.85rem;
                    line-height: 1.35;
                    letter-spacing: 0.02em;
                    word-wrap: break-word;
                    border: 1px solid #ccc;
                    border-radius: 6px;
                    padding: 10px;
                    background-color: #f9f9f9;
                    overflow: auto;
                    max-height: 800px;
                '
            >
                {highlighted}
            </div>
        """
    return (highlight_text,)


@app.cell
def _():
    search_term_input = mo.ui.text(debounce=50)
    return (search_term_input,)


@app.cell(hide_code=True)
def _():
    mo.md(r"""The `debounce=200` setting tells marimo to wait `200 ms` after the user stops typing before updating the value. That way the search doesn’t re-run on every single keystroke, but still feels responsive.""")
    return


@app.cell
def _(strings_from_suspicious_vads):
    unicode_text = strings_from_suspicious_vads.unicode.first().execute()
    return (unicode_text,)


@app.cell
def _(highlight_text, search_term_input, unicode_text):
    highlighted_unicode_text = highlight_text(unicode_text, search_term_input.value.strip())

    _html = mo.Html(highlighted_unicode_text).style(
        {
            "max-width": "800px",
        }
    )

    # Display the highlighted text
    mo.vstack([search_term_input, _html])
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## Exercise 3

    Create an interactive data app that lets you click through VADs from a table and drill down into one at a time. Add a search bar to run regular expression matches on the selected VAD, and display the results with a text highlighter. For inspiration, see the initial triage overview dashboard in the third notebook.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r""" """)
    return


if __name__ == "__main__":
    app.run()
