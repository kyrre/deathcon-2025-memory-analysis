import marimo

__generated_with = "0.17.0"
app = marimo.App(
    width="medium",
    app_title="Incident Response",
    layout_file="layouts/3_incident_response.grid.json",
    css_file="",
    sql_output="native",
)

with app.setup(hide_code=True):
    import ibis
    import marimo as mo
    import altair as alt
    import pyarrow as pa
    import ibis.selectors as s

    from ibis import _

    ibis.options.interactive = True


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    <div align="center">
      <img src="public/new-volatility-logo.png" style="max-width: 300px; margin-bottom: 0.5em;"/>
      <p style="
        font-size: 0.9em;
        font-weight: 600;
        margin: 0;
        font-family: system-ui, sans-serif;
      ">
          An initial triage overview for process injection
      </p>
    </div>
    In the two previous notebooks we introduced marimo and Ibis. Now, we’ll use them on a real forensics problem: *investigating a system for signs of process injection*.

    The idea is to replace ad-hoc commands with a repeatable triage workflow, all captured in a notebook that doubles as a lightweight dashboard.

    Say you have a system in your environment that’s acting strange. You check the EDR logs but don’t see any process that looks out of place. Your hunch is process injection, so you acquire a memory dump to take a closer look.

    An initial IR flow might look like this:

    **Wide sweep**  

    Run YARA against the raw memory image. If there’s a hit, pivot right away by investigating which memory region (VAD) held it, which process owned it, and dig deeper from there.

    **Plugins for detecting suspicious activity**  

    If nothing shows up, or when that lead runs out, use the Volatility plugins that look for suspicious behaviour, for example: 

    - threads that look out of place  
    - signs of hollowing or injection 
    - unbacked executable regions in `malfind`  
    - modules or DLLs from unusual paths  
    - suspicious handles or sockets

    Each of these adds context to the bigger picture, and together they create a repeatable “first-look” triage workflow.

    With marimo and Ibis, we can express this workflow programmatically by parsing plugin output, transforming and filtering it, and presenting it as tables that let you quickly pivot between suspicious processes.

    That’s the goal of this notebook: an automated triage dashboard for process injection.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""## Process Injection""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Since we are going to focus on identifying process injection on Windows systems in this notebook, we have included a short explanation here so the dataframe operations make more sense (and because it might be interesting too!).

    One way that malware can execute arbitrary code on a machine is by injecting code into a legitimate process. This makes it harder to detect what's been going on, compared to a scenario where for example `cmd.exe` spawns `reallybadprogram.exe`. With code injection, the malicious actions are probably performed by a completely normal process like `svchost.exe` or some other process that you would expect to see on the system even when nothing suspicious is going on. 

    Volatility has multiple built-in plugins for detecting code injection, and we'll make particular use of `malfind` and `suspicious_threads`. There are several ways to inject code. We will introduce some of them and explain how they can be detected, which also clarifies the algorithms behind the plugins. We won't cover everything, but this should help demystify process injection and the memory-forensics side of it, and then we'll put the knowledge to use shortly.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""### Remote DLL injection using `CreateRemoteThread`""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    **Technique**

    The attacker enables `SE_DEBUG_PRIVILEGE` so the process can read and write other processes' memory. It opens a handle to the victim, allocates memory with `VirtualAllocEx(..., PAGE_READWRITE)`, and writes the DLL path into that memory. By calling `CreateRemoteThread()` to invoke `LoadLibrary()` with the DLL path, the attacker causes the victim process to load the malicious DLL. Finally, the attacker frees the allocated memory and closes the handle.

    **Detection**

    The `dlllist` plugin can reveal unexpected modules. However, you need to suspect the process first, since checking every process is time consuming. It’s also not always obvious which DLL if any is malicious in a long list, so keep a baseline of DLLs a process normally loads. Useful indicators include suspicious load time or an unusual load count.

    <span class="paragraph" style="font-size: 1rem; padding-left: 5%;">
        *One caveat with that method is that the malicious DLL will only appear in the output from `dlllist` if it didn't unlink itself from the doubly linked list containing all the loaded modules for that process (data structure of type `_LDR_DATA_TABLE_ENTRY`). This is the structure that `dlllist` relies on. If it did unlink itself though, the DLL should still be visible in the output from the `ldrmodules` plugin which also parses the VAD tree in kernel memory for file-backed regions loaded into the process, even if they have been unlinked from by the malware in an attempt to hide its' activity.*
    </span>


    Another detection opportunity is when a DLL is packed on disk and must be unpacked in memory before execution. 

    The plugin `malfind` can spot this, so let's dive deeper into how it works.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.callout(
        mo.md(
            """

    `malfind` flags a VAD region if **all** of the following criteria apply:

    - The memory region is private (i.e. not backed by a file on disk) and has the VadS tag (meaning that it's a small heap allocation) **or** the memory region is file-backed with a protection string different from `PAGE_EXECUTE_WRITECOPY` (which is what's common for legitimately loaded DLLs).
    - The region is non-empty (memory actually committed). Meaning that there are bytes to execute here. As opposed to _reserved_ pages.
    - If the region is executable but not writable, it must contain at least one dirty page.

    For each region that passes these checks, malfind report process name and PID, start and end addresses, protection flags and VAD tag, commit and private memory info, a 64-byte hexdump and the associated disassembled version. `malfind` also adds a comment to the **`Note`** column if it finds an MZ header, a PE header, or a function prologue (which indicates shellcode), so keep an eye out for content in that column! 

    Note about `malfind` output: legitimate processes also satisfy the criteria sometimes, so not all the memory regions you see in the output from that plugin signify that process injection has taken place. Typically, the dissassembly for these entries don't make sense from a process injection point of view. You'll have to apply some context and understanding to conclude.


    """
        ),
        kind="info",
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""### Remote DLL injection using `QueueUserAPC`""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    **Technique**

    This is like remote DLL injection but targets a thread instead of a process. The attacker opens a handle to a target thread and calls `QueueUserAPC` with the function set to `LoadLibrary` and the parameter pointing at the DLL path in memory. When the thread next enters an alertable state, the APC runs and the DLL loads.

    **Detection**

    The detection options are the same as those of Remote DLL injection using `CreateRemoteThread`.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""### Remote shellcode injection""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    **Technique**

    Starts the same way as for DLL injection with:

    1. enable debug privileges
    2. open a handle

    However, instead of calling `LoadLibrary`, which is noisy, the attacker instead: 

    3. allocates memory in the victim process with `PAGE_EXECUTE_READWRITE` protection. The reason the region needs to be executeable, is because we are writing the code that will be executed. 


    5. sends shellcode (and not a DLL file path) into that memory region using `WriteProcessMemory`

    6.  calls `CreateRemoteThread` while pointing to the address where the code was written.

    **Detection**

    `malfind` can detect this. Can you see how? Check the info box above and map each condition to the injection steps.

    <span class="paragraph" style="font-size: 1rem; padding-left: 5%;">
    *If you see an MZ header in the hex dump / dissassembly output from `malfind`, it's almost certain that it's bad. If there's no MZ header, it can still be shellcode. Analyze the dissassembly to understand what it does.*
    </span>
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""### Reflective DLL injection""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    **Technique**

    The full DLL image is injected into an allocated region with a small loader stub (the *reflective loader*).

    A thread is started at the loader address using `CreateRemoteThread`. The loader then perfoms the same steps as `LoadLibrary`: relocations, import resolution, section mapping and `DllMain` invocation, all in memory.

    **Detection**

    As the forensic artefacts are the same as for the remote shellcode injection, `malfind` will detect this techinque.


    Cobalt Strike is a famous attack framework that uses reflective loading!
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""### Process Hollowing""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    **Technique**

    Unlike the earlier techniques, process hollowing creates a new process in a suspended state. The attacker unmaps the original image, writes a malicious image into that memory, then resumes the process so the injected code runs under the legitimate process name!

    **Detection**

    While `malfind` will not detect this technique based on the characteristics we just described, there is a [hollowprocesess](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.malware.hollowprocesses.html) plugin.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.callout(
        mo.md(
            """
    `suspicious_threads` is a different plugin that flags threads if they fit one of these criteria:

    - The thread is running from a non-file-backed memory region, i.e. the start address of the thread is a part of memory that isn't part of a PE image on disk, potentially indicating shellcode or injected code allocated via `VirtualAlloc` and `WriteProcessMemory`
    - The memory region where the thread starts has unusual protection flags, meaning something other than `PAGE_EXECUTE_WRITECOPY`
    - The VAD that hosts the thread maps a different executable than of the process executable that it is supposed to be. This is the case for process hollowing.

    """
        ),
        kind="info",
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""## Building dashboard components""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Now that we know a little bit about code injection, let's see if we can find any of it in this memory sample!""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ### Malfind

    Let's start by loading the data from the malfind plugin and rename the columns to use the snake_case naming convention, since we are in Python after all.
    """
    )
    return


@app.cell
def _():
    malfind = ibis.read_parquet("volatility_plugin_output/windows.malware.malfind.Malfind.parquet").rename("snake_case")

    malfind
    return (malfind,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Using the table widget is a big step up from the command line. You can click, filter, and sort the data instead of typing commands. But the tables can still be hard to read, so we’ll work on making them clearer.

    We’ll drop verbose columns like the hex dump and disassembly, then set the formatting for each column to improve readability.

    The UI component for rendering dataframes as tables is [mo.ui.table](https://docs.marimo.io/api/inputs/table/), which supports extensive customization.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    From the documentation, we see that you can assign a formatting function to each column using the format_mapping argument.

    ```python

    def format_process(col):
        return col.upper()

    format_mapping={
        "process": format_process
    }
    ```
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Let’s define a function to format columns with memory addresses in hexadecimal notation.""")
    return


@app.function
def format_hex_addr(addr):
    """Format integer address as hex string"""
    return f"0x{addr:016x}" if addr is not None else None


@app.cell(hide_code=True)
def _():
    mo.md(r"""We’ll also drop the `hexdump` and `disasm` columns, and turn off row selection along with the column statistics shown in the header.""")
    return


@app.cell
def _(malfind):
    mo.ui.table(
        # here we are using the selectors together with the negation operator ~
        # the effect -> select everything EXCEPT these two columns
        malfind.select(~s.cols("hexdump", "disasm")),
        # the function we defined above
        format_mapping={
            "start_vpn": format_hex_addr,
            "end_vpn": format_hex_addr,
        },
        # disable the ability select one or more rows
        selection=None,
        # disable the plots in the column header
        show_column_summaries=False,
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    This is already a significant improvement. However, we are not done yet. Let's continue by making the important parts more visible through the use of colors. Based on how malfind works, the most important fields to highlight are memory permissions and allocation tags.

    We can write a function that formats cells depending on the column and value. For example, in the `tag` column we’ll highlight `VadS` values. We’ll also color cells that show read-write and executable permissions.

    This is done by passing a function to the `style_cell` argument, which returns a dictionary of CSS properties.
    """
    )
    return


@app.function
def highlight_malware_indicators(row_id, column_name, value):
    """
    Color cells and apply monospace formatting for suspicious malware indicators.
    """

    colors = {
        "VadS": {"backgroundColor": "#ff9aa2", "color": "black"},
        "EXECUTE_READWRITE": {"backgroundColor": "#ffb7b2", "color": "black"},
        "EXECUTE": {"backgroundColor": "#ffdac1", "color": "black"},
        "1": {"backgroundColor": "#ff9999", "color": "black"},
    }

    # Highlight suspicious tag
    if column_name == "tag" and value == "VadS":
        return colors["VadS"]

    # Highlight suspicious protections
    if column_name == "protection":
        val = str(value)
        for exec_type in ("EXECUTE_READWRITE", "EXECUTE"):
            if exec_type in val:
                return colors[exec_type]

    # Highlight regions that aren't backed by a file on disk
    if column_name == "private_memory" and value == 1:
        return colors["1"]

    # Force monospace for VAD addresses
    if column_name in ("start_vpn", "end_vpn"):
        return {
            "fontFamily": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
            "whiteSpace": "nowrap",
        }

    # Force monospace for disassembly too
    if column_name == "disasm":
        return {
            "fontFamily": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
            "whiteSpace": "nowrap",
        }

    return {}


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    If you try to use a custom cell-highlighting function directly on an Ibis table, you’ll run into this error:

    ```plain
    NotImplementedError: Cell selection not supported
    ```

    This happens because `mo.ui.table` expects a concrete dataframe type that supports row and column access. An Ibis table expression is still just a lazy query plan, so that won't work. 

    The fix is to convert the Ibis table into an in-memory dataframe. You can choose the backend you like:

    - `t.to_pyarrow()` → PyArrow table  
    - `t.execute()` → pandas dataframe  
    - `t.to_polars()` → Polars dataframe  

    All of these will enable cell-highlighting. If you go with Polars, you’ll also gain more options for filtering and manipulation.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""After converting to a Polars dataframe, the table looks like this:""")
    return


@app.cell
def _(malfind):
    mo.ui.table(
        malfind.select(~s.cols("hexdump", "disasm", "file_output", "notes")).to_polars(),
        format_mapping={
            "start_vpn": format_hex_addr,
            "end_vpn": format_hex_addr,
        },
        text_justify_columns={"commit_charge": "right", "private_memory": "right"},
        selection=None,
        show_column_summaries=False,
        show_data_types=False,
        show_download=False,
        style_cell=highlight_malware_indicators,
        page_size=20,
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    So far, we’ve improved the table by adjusting alignment and disabling some default UI features.  
    Now we’ll refine the presentation to make the output clearer and easier to use.  

    The next changes are:

    - Reorder the columns so the most relevant fields come first  
    - Freeze key columns (`pid`, `process`, `tag`, `protection`) so they stay visible while scrolling  
    - Turn off extra UI features that aren’t needed here  
    - Bring back the disassembly column, styled to stay compact and readable  

    These refinements create a more structured, analyst-friendly view of the `malfind` output—ready to use in a triage dashboard.
    """
    )
    return


@app.cell
def _(malfind):
    _view = malfind.select(~s.cols("file_output", "notes", "hexdump")).select(
        "pid",
        "process",
        "tag",
        "protection",
        "start_vpn",
        "end_vpn",
        "commit_charge",
        "private_memory",
        "disasm",
    )

    formatted_malfind = mo.ui.table(
        _view.to_polars(),
        format_mapping={
            "start_vpn": format_hex_addr,
            "end_vpn": format_hex_addr,
        },
        freeze_columns_left=["pid", "process", "tag", "protection"],
        text_justify_columns={
            "pid": "right",
            "commit_charge": "right",
            "private_memory": "right",
        },
        selection=None,
        show_column_summaries=False,
        show_data_types=False,
        show_download=False,
        style_cell=highlight_malware_indicators,
        page_size=20,
    )

    formatted_malfind
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""What an improvement! Let's look at a few other UI elements we can use.""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    #### Exercise 1

    The `mo.stat` component is simple way to present statistics. Let’s build one that displays the number of unique processes flagged by `malfind`.  


    Take the `malfind` dataframe from earlier, perform a distinct count on `pid` and `process`, and display the result.  

    You can call `mo.stat` like this:

    ```python
    mo.stat(
        some_number_you_want_to_display,
        label="A title above your number",
        caption="A caption below your number",
    )
    ```
    """
    )
    return


@app.cell
def _():
    # Your code here...
    return


@app.cell(hide_code=True)
def _(malfind):
    _count = malfind.distinct(on=["pid", "process"]).count().execute()

    mo.stat(
        _count,
        label="Number of processes flagged by malfind",
        caption="Unique processes found in the malfind output",
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    A nice and efficient way to make information pop!

    It would also be useful to quickly see which processes were flagged, not just how many. A good UI component for this is `mo.ui.tabs`.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    #### Exercise 2

    Build a `mo.ui.tabs` component with two views:  

    - First tab: show the number from the previous exercise as a `mo.stat`  
    - Second tab: show an overview of the unique processes (`pid` and process name)  

    The syntax for `mo.ui.tabs` looks like this:

    ```python
    mo.ui.tabs(
        {
            "Name of tab1": whatever_you_want_to_display_in_tab1,
            "Name of tab2": whatever_you_want_to_display_in_tab2,
        }
    )
    ```
    """
    )
    return


@app.cell
def _():
    # Your code here...
    return


@app.cell(hide_code=True)
def _(malfind):
    _processes_with_malfind_alerts = malfind.distinct(on=["pid", "process"]).select("pid", "process").execute()

    mo.ui.tabs(
        {
            "Malfind": mo.stat(
                len(_processes_with_malfind_alerts),
                label="Number of processes flagged by malfind",
                caption="Click the Details tab so see which ones",
            ),
            "Details": _processes_with_malfind_alerts,
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    It may look like a small thing on its own, but you can probably see where this is heading.  

    Since we mentioned earlier that it’s worth checking the `notes` column, let’s do that programmatically and add a small component to the dashboard.  

    This is basically the same exercise, so we’ll show the solution right away. Still, you might want to try it yourself before moving on.
    """
    )
    return


@app.cell(hide_code=True)
def _(malfind):
    _malfind_notes = malfind.filter(_.notes.notnull()).select("pid", "process", "start_vpn", "notes").execute()
    mo.ui.tabs(
        {
            "Annotated malfind hits": mo.stat(
                len(_malfind_notes),
                label="Malfind hits where notes are present",
                caption="Regions with MZ headers, PE headers, or function prologues at the beginning",
            ),
            "Details": _malfind_notes,
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Turns out there are no notes to help us this time.  

    But if there were, that would be a strong lead to follow, so we wanted to include this component in the dashboard anyway.  

    On to the next plugin for more information - let’s take a look at `suspicious_threads`.
    """
    )
    return


@app.cell
def _():
    suspicious_threads = ibis.read_parquet("volatility_plugin_output/windows.malware.suspicious_threads.SuspiciousThreads.parquet").rename(
        "snake_case"
    )

    suspicious_threads
    return (suspicious_threads,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    This view highlights two processes, each with a thread showing multiple suspicious indicators.  
    These findings narrow the scope of analysis and clearly warrant further investigation.  

    Let’s add a tab for this as well: one side shows how many processes have suspicious threads, and the other lists which ones.  

    A useful addition to our dashboard.
    """
    )
    return


@app.cell(hide_code=True)
def _(suspicious_threads):
    _suspicious_threads_tab = suspicious_threads.distinct(on=["pid", "process"]).select("pid", "process").execute()

    mo.ui.tabs(
        {
            "Suspicious threads": mo.stat(
                len(_suspicious_threads_tab),
                label="Processes with suspicious threads",
                caption="Flagged by the suspicious_threads plugin. See the Details tab to see which ones.",
            ),
            "Details": _suspicious_threads_tab,
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Next, we want to build a larger `mo.ui.tabs` component that lets us quickly switch between plugin outputs.  
    We also want the option to drill down into a specific process.  

    For that, a dropdown listing the different PIDs is a good fit.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    #### Exercise 3

    Use the output of the `psscan` plugin to create a `mo.ui.dropdown` for our dashboard
    """
    )
    return


@app.cell
def _():
    # Your code here...
    return


@app.cell
def _():
    psscan = ibis.read_parquet("volatility_plugin_output/windows.psscan.PsScan.parquet").rename("snake_case").rename(process="image_file_name")

    _pids = psscan.select(_.pid).filter(_.pid.notnull()).distinct().order_by(_.pid).to_pyarrow().to_pylist()

    _pid_list = [row["pid"] for row in _pids if row["pid"]]
    _options = ["All"] + _pid_list

    pidproc_dropdown = mo.ui.dropdown(options=_options, value="All", label="Filter by PID")
    return pidproc_dropdown, psscan


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Here we take the output from `psscan`, extract the distinct process IDs, and sort them in ascending order.  
    The result is converted into a list of Python dictionaries, each containing the key `pid`.

    Based on this list, we created a handy little dropdown menu.
    """
    )
    return


@app.cell
def _(pidproc_dropdown):
    pidproc_dropdown
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    We now prepare the data for our dashboard by using the selected PID from the dropdown menu to filter out events that are not related to this process in the other tables.  

    First, we’ll load the tables into memory and rename some columns for consistency. For example, in the `netscan` output the process name is stored in the column `owner`.
    """
    )
    return


@app.cell
def _():
    vadinfo = ibis.read_parquet("volatility_plugin_output/windows.vadinfo.VadInfo.parquet").rename("snake_case")
    handles = ibis.read_parquet("volatility_plugin_output/windows.handles.Handles.parquet").rename("snake_case")
    netscan = ibis.read_parquet("volatility_plugin_output/windows.netscan.NetScan.parquet").rename("snake_case")
    ldrmodules = ibis.read_parquet("volatility_plugin_output/windows.ldrmodules.LdrModules.parquet").rename("snake_case")
    dlllist = ibis.read_parquet("volatility_plugin_output/windows.dlllist.DllList.parquet").rename("snake_case")
    return dlllist, handles, ldrmodules, netscan, vadinfo


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    We can define a  function to filter the data using the selected PID.  This makes the code easier to reuse in different parts of the dashboard.

    Feel free to try this yourself, or use our version below.
    """
    )
    return


@app.function
def filter_by_pid(df, pid_value):
    if pid_value == "All":
        return df
    else:
        return df.filter(_.pid == pid_value)


@app.cell
def _(
    dlllist,
    handles,
    ldrmodules,
    malfind,
    netscan,
    pidproc_dropdown,
    suspicious_threads,
    vadinfo,
):
    filtered_netscan = filter_by_pid(netscan, pidproc_dropdown.value)
    filtered_malfind = filter_by_pid(malfind, pidproc_dropdown.value)
    filtered_suspicious_threads = filter_by_pid(suspicious_threads, pidproc_dropdown.value)
    filtered_dlllist = filter_by_pid(dlllist, pidproc_dropdown.value)
    filtered_ldrmodules = filter_by_pid(ldrmodules, pidproc_dropdown.value)
    filtered_handles = filter_by_pid(handles, pidproc_dropdown.value)
    filtered_vadinfo = filter_by_pid(vadinfo, pidproc_dropdown.value)
    return (
        filtered_dlllist,
        filtered_handles,
        filtered_malfind,
        filtered_netscan,
        filtered_suspicious_threads,
        filtered_vadinfo,
    )


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Thanks to marimo’s reactive execution model, all the tables above are now filtered automatically 
    by the selected PID.  

    Change the PID in the dropdown and see how the `filtered_netscan` output updates!
    """
    )
    return


@app.cell
def _(filtered_netscan):
    filtered_netscan
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    We can now combine these into a single tab view and apply styling the same way as we did for malfind. 

    Feel free to play around with this!
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""### Handles""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Below we’ve defined a highlighting function for handles too. It marks handles of type Process, as well as those pointing to an object owned by another process.

    Another angle would be to use the granted_access field. Process hollowing, for example, requires at least `PROCESS_VM_WRITE` and `PROCESS_VM_OPERATION` (mask 0x28) to call WriteProcessMemory. But these permissions are so common that they don’t stand out as a useful highlight.

    You'll discover more and more things that are unusual the more you work with memory samples and you can keep working on these notebooks as you learn to highlight interesting things!
    """
    )
    return


@app.cell
def _(pidproc_dropdown):
    def highlight_handle_indicators(row_id, column_name, value):
        """
        Color certain cells and format hex values in the handles plugin output
        """

        colors = {
            "Process": {"backgroundColor": "#ff9999", "color": "black"},
            "Other_process": {"backgroundColor": "#ffff99", "color": "black"},
        }

        # Highlight handles to processes
        if column_name == "type" and value == "Process":
            return colors["Process"]

        selected_pid = pidproc_dropdown.value

        if (
            column_name == "name"
            and selected_pid != "All"
            and value
            and "Pid " in value
            and not value.endswith(f"Pid {selected_pid}")
        ):
            return colors["Other_process"]

        # Force monospace for columns with hex values
        if column_name in ("granted_access", "offset"):
            return {
                "fontFamily": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
                "whiteSpace": "nowrap",
            }

        return {}
    return (highlight_handle_indicators,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    We can now combine all the tables in a `mo.ui.tabs` component. This lets you pivot between the data sources and drill down by PID.

    While we have highlighted a few of the values that stand out, there are many other ways to use custom styling, so we encourage you to share your own ideas on Discord or social media.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.center(
        mo.callout(
            mo.md(
                r"""
            Lazy Loading with `mo.lazy`
            ---

            Since these tables can be expensive to render (especially with large datasets), we'll use [`mo.lazy`](https://docs.marimo.io/api/layouts/lazy/#marimo.lazy) to defer computation until a tab is actually clicked.

            This improves the initial load time of the notebook by only rendering the active tab's content.

            **Usage**: Wrap expensive components directly with `mo.lazy(component)`.
            """
            ),
            kind="info"
        ).style({"max-width": "800px"})
    )
    return


@app.cell
def _(
    filtered_dlllist,
    filtered_handles,
    filtered_malfind,
    filtered_netscan,
    filtered_suspicious_threads,
    filtered_vadinfo,
    highlight_handle_indicators,
    pidproc_dropdown,
    psscan,
):
    mo.ui.tabs(
        {
            "psscan": mo.lazy(mo.ui.table(
                psscan.drop(["threads", "handles", "session_id", "wow64", "file_output"]),
                format_mapping={
                    "offset(v)": format_hex_addr,
                },
                selection=None,
                show_column_summaries=False,
            )),
            "malfind": mo.lazy(mo.vstack(
                [
                    pidproc_dropdown,
                    mo.ui.table(
                        filtered_malfind.drop(["hexdump", "disasm", "file_output"]).to_polars(),
                        format_mapping={"start_vpn": format_hex_addr, "end_vpn": format_hex_addr},
                        selection=None,
                        show_column_summaries=False,
                        style_cell=highlight_malware_indicators,
                    ),
                ]
            )),
            "vadinfo": mo.lazy(mo.vstack(
                [
                    pidproc_dropdown,
                    mo.ui.table(
                        filtered_vadinfo,
                        format_mapping={
                            "offset": format_hex_addr,
                            "start_vpn": format_hex_addr,
                            "end_vpn": format_hex_addr,
                            "parent": format_hex_addr,
                        },
                        selection=None,
                        show_column_summaries=False,
                    ),
                ]
            )),
            "suspicious_threads": mo.lazy(mo.vstack(
                [
                    pidproc_dropdown,
                    mo.ui.table(
                        filtered_suspicious_threads,
                        format_mapping={
                            "address": format_hex_addr,
                        },
                        selection=None,
                        show_column_summaries=False,
                    ),
                ]
            )),
            "dlllist": mo.lazy(mo.vstack(
                [
                    pidproc_dropdown,
                    mo.ui.table(
                        filtered_dlllist,
                        format_mapping={
                            "base": format_hex_addr,
                        },
                        selection=None,
                        show_column_summaries=False,
                    ),
                ]
            )),
            "ldrmodules": mo.lazy(mo.vstack(
                [
                    pidproc_dropdown,
                    mo.ui.table(
                        filtered_dlllist,
                        format_mapping={
                            "base": format_hex_addr,
                        },
                        selection=None,
                        show_column_summaries=False,
                    ),
                ]
            )),
            "netscan": mo.lazy(mo.vstack(
                [
                    pidproc_dropdown,
                    mo.ui.table(
                        filtered_netscan,
                        format_mapping={
                            "offset": format_hex_addr,
                        },
                        selection=None,
                        show_column_summaries=False,
                    ),
                ]
            )),
            "handles": mo.lazy(mo.vstack(
                [
                    pidproc_dropdown,
                    mo.ui.table(
                        filtered_handles.to_polars(),
                        format_mapping={
                            "offset": format_hex_addr,
                            "granted_access": format_hex_addr,
                        },
                        selection=None,
                        show_column_summaries=False,
                        style_cell=highlight_handle_indicators,
                    ),
                ]
            )),
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""### Info""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""The info plugin shows details about the operating system of the memory dump, which is useful to include in the dashboard.""")
    return


@app.cell
def _():
    info = ibis.read_parquet("volatility_plugin_output/windows.info.Info.parquet")
    return (info,)


@app.cell
def _(info):
    info
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    #### Exercise 4

    Build a UI component that presents the output of the info plugin in a clear and compact way.

    The raw table is a bit awkward since it only contains two columns (variable, value). Remember that you’re not limited to a table - you can also use HTML, Markdown, or other UI elements to format the data. You can also pass a Python list to the `mo.ui.table` function.

    For the solution, we’ll keep it simple and stick with a UI table, but feel free to experiment with alternative layouts.
    """
    )
    return


@app.cell
def _():
    # Your code here..
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Here we render the data as a table, wrapped in mo.Html to restrict the width. The same effect could also be achieved with the style method,.""")
    return


@app.cell
def _(info):
    _info = info.filter(~_.Variable.contains("layer"), ~_.Variable.contains("Symbol"))

    _view = mo.ui.table(
        _info.to_polars(),
        selection=None,
        show_column_summaries=False,
        show_data_types=False,
        show_download=False,
        page_size=50,
        text_justify_columns={"Variable": "left", "Value": "left"},
    )

    mo.Html(
        f"""
        <div style="width: 500px">
            {_view}
        </div>
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""As we mentioned, it’s rare for a single plugin to give you the answer in a forensic investigation. You usually need to run several and then correlate their output. Automating some of that correlation could help narrow the analysis!""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    #### Exercise 5

    Create a function that finds processes that appear in the outputs of multiple plugins (matched by PID and process name). Then use it to show the overlap between `malfind` and `suspicious_threads`.
    """
    )
    return


@app.cell
def _():
    # Your code here...
    return


@app.function(hide_code=True)
def find_overlap(output_plugin1, output_plugin2):
    return (
        output_plugin2.join(
            output_plugin1,
            predicates=[
                output_plugin1["process"] == output_plugin2["process"],
                output_plugin1["pid"] == output_plugin2["pid"],
            ],
        )
        .select("process", "pid")
        .distinct(on=["pid", "process"])
    )


@app.cell(hide_code=True)
def _(malfind, suspicious_threads):
    mo.ui.table(
        find_overlap(malfind, suspicious_threads),
        selection=None,
        show_column_summaries=False,
        show_data_types=False,
        label="Overlap between malfind and suspicious threads"
    ).style({"width": "500px"})
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Based on what we have observed so far, this process qualifies for a more thorough analysis. However, we won’t reverse it here. Feel free to do that yourself if you want to practice, but for this workshop we’ll continue building the triage dashboard. Still, it’s useful to outline what a typical workflow for pursuing this lead looks like:  

    First, identify which VAD contains the malware. From the `notes` column in the `malfind` output we saw that volatility didn’t detect any MZ headers at the beginning of the VAD hexdumps. The MZ header isn’t always at the start. Sometimes junk data comes first, so it doesn’t always appear in the hexdump output. If the right VAD isn’t obvious, dump all VADs for the process and scan them with YARA to locate the suspicious one. Once found, remove any junk before the MZ header, then open it in a disassembler or decompiler. Always run `strings`, and check loaded libraries and exported functions to get a starting point for analysis. We repeat: never skip `strings`.  

    You can also examine the `OneDrive.exe` process in the output from other plugins such as `dlllist`, `handles`, or `ldrmodules`. Some of this work can’t be automated and requires manual exploration. Our triage dashboard helps surface such leads. Even though we have a clear lead in `OneDrive.exe`
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    We encourage you to explore the `OneDrive.exe` lead with some of the other plugins. Can you find useful insights by cross-checking outputs from `netscan`, `netstat`, `dlllist`, `ldrmodules`, and so on?  

    Remember, we already prepared the `mo.ui.tabs` component with all these outputs and a PID filter. Notice how much easier this is compared to scrolling through raw Volatility text in the terminal.  

    It can also be helpful to look for overlaps. For example, check which of the processes flagged by `malfind` also have network connections.
    """
    )
    return


@app.cell
def _(malfind, netscan):
    overlap_netscan_malfind = find_overlap(netscan.rename(process="owner"), malfind)
    overlap_netscan_malfind
    return


@app.cell
def _(netscan):
    netscan.rename(process="owner").filter(_.process == "OneDrive.exe")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    If this were a real incident response case, it would be worth checking that IP in other logs, such as network flow data, or running some CTI investigations. It could also turn out to be normal behavior for OneDrive. When conducting an investigation, you need to follow the leads and see where they take you.  

    **OpSec Reminder**: Don’t poke suspected C2 infrastructure. Always keep your analysis in a lab environment to avoid tipping off adversaries or putting yourself at risk.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    #### Exercise 6

    Build a process-injection triage dashboard in *App view*. Reuse the components we explored earlier, and add new ones if helpful. For example, you could add a title as a markdown cell like this:

    ```python
    title = mo.md('## Volatility Triage Dashboard for Process Injection')
    ```
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    #### Exercise 7 (extra credit)

    Create a function that lets you find the _difference_ between two plugin outputs, and then display it. This makes sense for example in the case of `pslist` and `psscan`, or `dlllist` and `ldrmodules`, or `netstat` and `netscan`, to see if the malware potentially attempted to hide something (a process, a loaded module or a network connection in these three examples). Maybe you event want to let the analyst choose the modules to compare with a dropdown menu?

    We won't provide a solution for this - it is left as an exercise to the workshop attendee!
    """
    )
    return


if __name__ == "__main__":
    app.run()
