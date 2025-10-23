import marimo

__generated_with = "0.17.0"
app = marimo.App(width="medium", css_file="", sql_output="native")


@app.cell(hide_code=True)
def _():
    import math
    import marimo as mo
    return math, mo


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        """
    <div align="center">
        <img src="public/marimo-logotype-thick.svg" style="height: 15em; width: 15em; margin-bottom: -10px;"/>
        <p>An introduction to <a href="https://docs.marimo.io/getting_started/key_concepts/">marimo</a> for memory analysis</p>
    </div>
    <hr/>


    In the last video we ran Volatility plugins from the CLI, and then looked at how their output can be pulled into a notebook and treated as a data analysis task.  

    That idea isn’t new. You’ve probably seen the same done in Jupyter with Sentinel or Splunk, and maybe you’ve come across Microsoft’s [msticpy](https://msticpy.readthedocs.io/en/latest/) package.  

    What’s different here is that we’ll apply the same approach to *memory forensics data*.  

    For this, we’ll use *marimo*. It treats the notebook as a Python web app and avoids many of the issues you’ve seen in Jupyter.  

    The key difference is marimo’s *reactive execution model*. When you change a variable, every dependent cell updates automatically. With built-in UI components, this lets us turn a notebook into a small interactive data app, perfect for exploring Volatility output.
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""Let’s try it out. We’ll define a variable in one cell and use it in another, and watch how marimo reacts when the value changes.""")
    return


@app.cell
def _():
    # try changing me!
    try_changing_me = 10
    return (try_changing_me,)


@app.cell
def _(try_changing_me):
    try_changing_me
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    Several cells can depend on the same value, and marimo keeps them in sync when it changes.  
    However, you can’t redefine that variable in another cell.  

    ```python
    try_changing_me = 10  # redefining this in another cell will cause an error
    ```
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""To see how reactivity works with interactive controls, we’ll try it out with a drop-down menu.""")
    return


@app.cell
def _(mo):
    plugin = mo.ui.dropdown(["pslist", "netscan", "malfind"], value="pslist", allow_select_none=False)

    plugin
    return (plugin,)


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""Changing the drop-down updates the `plugin.value` attribute.""")
    return


@app.cell
def _(plugin):
    plugin.value
    return


@app.cell(hide_code=True)
def _(mo):
    # This is the definition of the callout box you just saw rendered above.
    # As you can see, we’re mixing a bunch of marimo components together. How meta! 😼

    mo.center(
        mo.callout(
            mo.md(
                r"""
            UI components
            ---

            marimo comes with many [UI components](https://docs.marimo.io/api/inputs/) and [layouts](https://docs.marimo.io/api/layouts/).  
            These let you turn a plain notebook into an interactive app.  

            Some examples:  

            - *Inputs*: sliders, text boxes, dropdowns, radio buttons, checkboxes, date pickers, file pickers  
            - *Layouts*: sidebars, tab views, grids, accordions, carousels  
            - *Tools*: data frame browsers, code editors, media and video players  

            We won’t try to cover everything here. Instead, we’ll introduce components as we need them, while building tools for memory forensics.
            """
            )
        ).style({"max-width": "800px"})
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(rf"""It’s called a workshop for a reason, so let’s jump straight into the exercises!""")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        """
    ## Exercise 1

    Use `mo.ui.text(debounce=100)` with a placeholder for process names.  

    Make a text input and show its value.  
    Use marimo’s reactive execution so the display updates as you type.
    """
    )
    return


@app.cell
def _():
    # Define the `mo.ui.text(debounce=100)` variable here.
    return


@app.cell
def _():
    # Display its value here.
    # You can simply print it, or pass it into another UI component like mo.md(f"...").
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    Most exercises come with a suggested solution.  

    Click the *Solution* header below to reveal it.
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.accordion(
        {
            "Solution": mo.md("""
        ```python
        # Cell 1:
        process_name = mo.ui.text(placeholder="Enter process name", debounce=100)
        process_name

        # Cell 2:
        mo.md(f"You entered: {process_name.value}")
        ```
        """)
        }
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    ## Markdown  

    We’ve been using markdown cells throughout this notebook. They’re one of marimo’s built-in cell types, and you can add or remove them just like code cells.  

    Under the hood, a markdown cell is just a call to [`mo.md`](https://docs.marimo.io/api/markdown/#marimo.md). It takes a markdown string and renders it as HTML.  

    Because it’s just Python, you can:  

    - drop values into text with f-strings  
    - mix markdown with raw HTML  
    - write inline math or custom-styled blocks  

    Here’s one cell that shows all of that in action:
    """
    )
    return


@app.cell(hide_code=True)
def _(math, mo, plugin):
    mo.md(
        rf"""
    <div align="center" style="margin-top: 40px;">
        The dropdown plugin is currently set to: {mo.md(f"**{plugin.value}**")}
    </div>

    --- 

    √2 ≈ **{math.sqrt(2):.3f}**.

    --- 

    Here’s Euler’s identity:

    \[
        e^{{i \pi}} + 1 = 0
    \]

    ---

    <div style="padding:10px; background:#f0f4ff; border:1px solid #c0c8e0; border-radius:6px;">
        <strong>Styled box:</strong> This is interpolated value → <span style="color:#d14;">{plugin.value}</span>
    </div>

    ---

    <div align="center" style="margin-bottom: 40px">
      The 
      <span style="
        font-weight:bold;
        background: linear-gradient(90deg, #4a90e2, #d4145a);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      ">mo.md</span> function is 
      <span style="
        font-weight:900;
        color:#111;
        padding:2px 8px;
        border:4px solid #111;
        letter-spacing:1px;
      ">OP</span>
    </div>
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""We’ve looked at how to style and present content, now let’s bring some data into the system.""")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        """
    <div align="center">
        <img src="public/DuckDB_logo.svg" style="height: 15em; width: 15em; margin-bottom: 30px;"/>
    </div>

    In marimo you can use both *Python and SQL* together. Every notebook has a DuckDB 
    connection available by default, so no setup is needed.  

    *What is DuckDB?*  

    DuckDB is an embedded analytical database. It runs inside your Python process with zero 
    configuration. There is no server to start and no connections to manage.  

    *Key features*  

    1. *Direct file querying*: Query Parquet, CSV, or JSON files without loading them fully 
       into memory.  

    2. *In-memory tables*: Create tables that appear in marimo’s data sources panel and can be 
       used throughout the notebook.  

    3. *Persistent databases*: Save and connect to DuckDB database files on disk when you want 
       tables and data to be available across sessions.
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    # We can also use mo.Html directly to render a HTML string.
    mo.Html(
        r"""
        <p align="center" style="font-size:1.2em; margin:30px 0;">
          <strong style="margin:0 6px;">"SQLite for analytics"</strong> 
          <br/>
          <span title="intense handwaving">👋</span>
        </p>
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        """
    Create SQL cells in any of these ways:

    - Right-click the *Add Cell* button next to a cell  
    - Use *Convert to SQL* in the cell menu  
    - Click *Add SQL Cell* at the bottom of the page  

    marimo runs SQL through the `mo.sql()` function:

    ```python
    result_df = mo.sql(f"SELECT * FROM my_table LIMIT {max_rows.value}")
    ```

    The output type is configurable. By default results show in marimo’s table view, but you
    can set them to return a dataframe instead. Queries can also use Python variables and UI
    values, so results update reactively.
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.center(
        mo.callout(
            mo.md(rf"""
            *Data sources*
            ---

            Use the {mo.icon("lucide-database", inline=True, size=14)} icon in the left toolbar  to explore all dataframes and in-memory tables available in this notebook.
            """)
        ).style({"max-width": "600px"})
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    ### Querying Volatility Data with DuckDB

    Our first example uses output from Volatility’s *pslist* plugin.  
    This plugin lists the processes that were running in a Windows memory dump.

    DuckDB gives us two ways to work with this data:

    1. *Direct file query* - read the Parquet file produced by Volatility without loading it into memory:

       ```bash
       uv run vol -f CLIENT-02.dmp -r parquet windows.pslist > volatility_plugin_output/windows.pslist.PsList.parquet
       ```
    2. *In-memory tables* - load the data into the notebook’s database for repeated queries.

    We’ll start by querying the Parquet file directly to see the process list.
    """
    )
    return


@app.cell
def _(mo):
    # Direct file querying - no need to load the entire file into memory
    volatility_data = mo.sql(
        f"""
        SELECT
            *
        FROM
            read_parquet(
                'volatility_plugin_output/windows.pslist.PsList.parquet'
            )
        LIMIT
            10
        """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""The output is a table with ten rows from the pslist plugin, read directly from the Parquet file. This is already useful because it lets us inspect Volatility data without any extra steps.""")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""Next, we’ll load the data into an in-memory table. It will show up in the "Data sources" panel and can be reused across multiple queries in this notebook.""")
    return


@app.cell
def _(mo):
    process_list = mo.sql(
        f"""
        CREATE OR REPLACE TABLE process_list AS
        SELECT
            *
        FROM
            read_parquet(
                'volatility_plugin_output/windows.pslist.PsList.parquet'
            );

        SELECT
            *
        FROM
            process_list;
        """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    The `process_list` table now appears in the Data sources panel and can be reused anywhere in the notebook. Time to practice a few queries.  

    *Note: if SQL isn’t your thing, don’t worry. You can skip ahead, peek at the solution, and move on. For the rest of the workshop we’ll use a dataframe API, which we’ll introduce in the next notebook.*
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        """
    ### Exercise 2

    Write a query that does two things:   

    1. Count the total number of processes.  
    2. Find the process with the highest PID.

    *Hint: you’ll probably want to use `COUNT(*)` and `MAX(pid)`.*
    """
    )
    return


@app.cell
def _(mo):
    _df = mo.sql(
        f"""
        -- Your query here
        """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.accordion(
        {
            "Solution": mo.md("""
        ```sql
        SELECT 
            COUNT(*) as total_processes,
            MAX(PID) as highest_pid
        FROM process_list
        ```
        """)
        }
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        """
    ### Exercise 3

    Find the PIDs of the `explorer.exe` and `OneDrive.exe` processes.

    *Hint: use a `WHERE` clause to filter by the process name.*
    """
    )
    return


@app.cell
def _(mo):
    _df = mo.sql(
        f"""
        -- Your query here
        """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.accordion(
        {
            "Solution": mo.md("""
        ```sql
        SELECT PID, ImageFileName
        FROM process_list
        WHERE ImageFileName IN ('explorer.exe', 'OneDrive.exe')
        ORDER BY ImageFileName
        ```
        """)
        }
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    ---
    <div align="center" style="margin: 2em 0; font-size: 1.1em; color:#666;">
      Up to now we’ve been working with data tables and queries.<br/>
      Next, let’s look at how to <em>see</em> the data.
    </div>
    ---
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    ## Visualizations

    marimo works with all the common plotting libraries. 
    Among them, *Altair* and *Plotly* have special support: they stay reactive and update automatically when the data changes.  

    Visualization is a huge topic on its own. Here we’ll just take a quick tour of a few features in [Altair](https://altair-viz.github.io/) to get a sense of how it fits into our workflow.
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    ### Altair 

    Altair is a *declarative grammar of graphics* for Python.  
    You don’t write drawing instructions. You say how your data maps to visuals (x, y, color, size …), and Altair builds the chart.  

    Altair includes built-in interaction like tooltips, brushing, and selections.  
    marimo adds reactivity: selections from a chart can flow back into Python as filtered DataFrames.  

    Together, they let you turn plugin output into interactive visual summaries with little code.
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    We’ll show Altair in action by plotting the k most common DLLs.  

    Steps:  

    1. *Compute stats with DuckDB*  
       Use the `DllList` plugin output to find the k most common DLLs.  

    2. *Add a slider*  
       Control how many DLLs to include by adjusting k.  

    3. *Build the chart with Altair*  
       Draw a bar chart using Altair’s declarative style.  

    4. *Add details*  
       Hovering over a bar shows info about the DLL and which processes load it.
    """
    )
    return


@app.cell
def _(k, mo):
    dlls = mo.sql(
        f"""
        WITH counts AS (
            SELECT
                Name,
                COUNT(DISTINCT PID) AS procs
            FROM read_parquet('volatility_plugin_output/windows.dlllist.DllList.parquet')
            GROUP BY Name
        ),
        most_common AS (
            SELECT
                'Most common' AS grp,
                Name,
                procs
            FROM counts
            ORDER BY procs DESC
            LIMIT {k.value}
        )
        SELECT grp, Name, procs FROM most_common;
        """,
        output=False
    )
    return (dlls,)


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    This query uses common table expressions (CTEs) to first count DLL usage, then pick the *k* most and least common.  
    Notice that *k* is written as a Python f-string argument. Even though `k` isn’t defined yet, marimo will resolve it later because of its dependency tracking.
    """
    )
    return


@app.cell
def _(mo):
    k = mo.ui.slider(start=5, value=10, stop=50, label="Most common DLLs")
    k
    return (k,)


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""And now we define the slider that sets the *k* value for the query *above*.""")
    return


@app.cell
def _(dlls, k):
    import altair as alt

    chart = (
        alt.Chart(dlls)
        .mark_bar()
        .encode(
            y=alt.Y("Name:N", title="DLL", sort="-x"),
            x=alt.X("procs:Q", title="# Processes", axis=alt.Axis(grid=False)),
            tooltip=["Name", "procs"],
        )
        .properties(
            width=700,
            height=800,
            title=f"DLLs by number of processes loaded into (The {k.value} most common dlls)",
        )
        .interactive()
    )
    chart
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    This builds a bar chart from the query results. 


    The x-axis shows how many processes load each DLL, and the y-axis lists the DLL names.  
    The title also includes the current value of *k*, so it updates as the slider changes.
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    To sum up:  

    - The DuckDB query counts how many processes load each DLL, then picks the *k* most and least common.  
    - Altair maps the results into a bar chart:  
      - y-axis → DLL name  
      - x-axis → number of processes  
    - Altair handles sorting, tooltips, and interaction.  
    - The slider sets *k*, and changing it updates both the query and the chart.
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""Later in the course we’ll look at building custom visualizations.  For now, let’s move on to the AI features.""")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        rf"""
    <div align="center" style="margin-bottom: 12px;">
      {mo.icon("lucide-sparkles", size=36)}
    </div>

    marimo isn’t just a notebook. It’s also an *AI-powered editor*.  

    In practice, this means you can:  

    - generate new cells from a prompt  
    - refactor existing ones  
    - scaffold whole notebooks  
    - use inline completions (like GitHub Copilot)  

    The AI assistant is *data-aware*: it sees your variables, dataframe shapes, and database schemas.  
    That extra context makes it better at writing queries, joining tables, and building charts than a typical code assistant.
    """
    )
    return


@app.cell
def _(mo):
    mo.md(r"""You are probably using AI already. So let's just set things up and get started.""")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    ### Exercise 4

    Visit the [official docs](https://docs.marimo.io/guides/editor_features/ai_completion/#generating-cells-with-ai) and set up an AI provider.

    *Steps:*

    1. Pick a provider you can use.
    2. Create an API key.
    3. Add the key to your environment or marimo settings.
    4. Restart the notebook.

    *Verify:*

    - Use the editor’s AI command to *generate a new cell* from a short prompt.
    - If a cell appears and runs, you’re set.
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        rf"""
    ### Exercise 5  

    Use the {mo.icon("lucide-sparkles")} button in the panel to generate some Python or SQL code.  

    Vibes investigation.
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        rf"""
    ### Exercise 6  

    Click the {mo.icon("lucide-bot-message-square")} icon on the left.  
    Use the AI chat to ask questions about `process_list`.
    """
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(
        r"""
    We’ve covered some of marimo’s main features, but there’s much more in the docs — things like caching, state, and custom UI.  
    There’s also a YouTube channel and a Discord community that are worth checking out if you want to go deeper.  

    For now, we have enough to get going. We’ll introduce more features as we need them.  

    Up to this point we’ve been using DuckDB and SQL. That works well, but it can feel complicated if you’re not a SQL expert.  
    Another option is to work with data frames directly in Python.  

    Here we’ll use the *Ibis DataFrame library*.  

    You can still use Pandas, Polars, or another library if you prefer.  
    But Ibis is worth learning, since it also shows up in other contexts - BigQuery, Athena, Databricks, Snowflake, and other systems used in detection and response work.
    """
    )
    return


if __name__ == "__main__":
    app.run()
