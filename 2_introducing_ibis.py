import marimo

__generated_with = "0.16.0"
app = marimo.App(
    width="medium",
    app_title="Ibis",
    css_file="",
    sql_output="native",
)

with app.setup(hide_code=True):
    import ibis
    import marimo as mo


@app.cell(hide_code=True)
def _():
    mo.md(
        rf"""
    <div align="center">
        <img src="public/ibis.svg" style="height: 15em; width: 15em; margin-bottom: -10px;"/>
        <p>An introduction to <a href="https://ibis-project.org/">Ibis</a> for memory analysis</p>
    </div>
    <hr/>

    In the last notebook we used marimo and DuckDB to query Volatility output.  This was an improvement over working on the command line, but it involves writing SQL.

    SQL is fine, but it has some drawbacks:

    - hard to reuse across notebooks  
    - hard to test like normal code  
    - messy when queries get long  

    Many analysts prefer dataframe APIs instead.  
    *Ibis* gives you that kind of interface, while still running on backends like DuckDB, Snowflake, ClickHouse, and BigQuery.

    ## Ibis

    Ibis builds queries with *deferred execution*. You describe what you want in Python, and Ibis translates it into SQL for your backend.

    Example in Python:

    ```python
    t = (
        con.table("malfind")
          .select("PID", "Process")
          .filter(_.PID != 4)
    )
    ```

    With DuckDB, this becomes:

    ```sql
    SELECT "PID", "Process"
    FROM "malfind"
    WHERE "PID" <> 4
    ```

    Using Ibis makes it easier to explore Volatility outputs, join data across plugins, and build small analysis routines without getting lost in SQL.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.callout(
        mo.md(
            """
            Aside
            -----

            **Threat detection and response + Ibis**

            Enterprises rarely rely on a single data system.  
            In a large organization you might see:

            - **Snowflake** for business analytics  
            - **Databricks** on object storage for a security data lake  
            - **ClickHouse** powering SIEMs like RunReveal  
            - **Athena** for AWS VPC logs in S3  
            - Microsoft Sentinel’s data lake, queried with PySpark  

            Each has its own SQL dialect, but with Ibis you write Python dataframe expressions once and run them across all of them.
            """
        )
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Let’s see how this works on our Volatility data.  

    With Ibis you normally start by creating a connection to a backend, for example:

    ```python
    con = ibis.databricks.connect(...)
    ```

    Since we’re using DuckDB (default), we don’t need that step. We can load Parquet files directly with `ibis.read_parquet`.

    For those familiar with SQL: calling `read_parquet` creates a [temporary table](https://duckdb.org/docs/stable/sql/statements/create_table.html#temporary-tables) in a catalog named `temp`.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""We can load the `pslist` output into Ibis with `read_parquet`.""")
    return




@app.cell
def _():
    processes = ibis.read_parquet(
        "volatility_plugin_output/windows.pslist.PsList.parquet",
    )

    processes
    return (processes,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Notice that nothing happened yet. 
    What we see is just a representation of the query. It hasn’t been executed.

    To run it, call one of these methods. Each will return the result in a different dataframe format:

    1. `.execute()` or `.to_pandas()` → pandas DataFrame  
    2. `.to_polars()` → Polars DataFrame  
    3. `.to_pyarrow()` → PyArrow table
    """
    )
    return


@app.cell
def _(processes):
    _results = processes.to_polars()
    _results
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        rf"""
    Now the query has executed and returned a Polars table, which marimo rendered with the built-in table widget.  

    Take a moment to notice how much easier and more pleasant this is to look at than command-line output.  

    The [table](https://docs.marimo.io/api/inputs/table/) widget has many features, which we’ll cover in the next notebook.  
    For now, let’s try some of its core functionality in a few exercises.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        rf"""
    ## Exercise 1

    Use the search feature {mo.icon("lucide-search", inline=True, size=12)} in the bottom-left of the table widget to find and count the number of `cmd.exe` processes.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Solution": mo.md("""
         There are two `cmd.exe` processes.
        """)
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        rf"""
    ## Exercise 2

    Use the column explorer {mo.icon("lucide-chart-column-stacked", inline=True, size=12)} to find the most common process name.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Solution": mo.md("""
         It's `svchost.exe`.
        """)
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## Interactive mode

    By default Ibis uses deferred execution.  
    You can switch to eager execution by enabling interactive mode:

    ```python
    ibis.options.interactive = True
    ```

    Be careful with this on backends like BigQuery, since it can trigger long-running queries whenever ancestor cells change.

    With our in-memory DuckDB tables from Volatility, this is exactly what we want.
    It also makes Ibis feel more like working with pandas.
    """
    )
    return


@app.cell
def _():
    ibis.options.interactive = True
    return


@app.cell
def _(processes):
    processes
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Now that interactive mode is on, we can work with Ibis tables more directly.  

    Instead of calling `.to_pyarrow()` or `.execute()`, we can write expressions and see the results right away.   

    This makes it easy to explore data step by step, just like with pandas.

    Next, let’s look at how to transform tables and columns using Ibis operations.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## Table and column operations

    We loaded the Parquet dataset into an Ibis table and used the built-in `mo.ui.table` widget to explore it. 

    From here, we can transform the data by chaining table operations like `filter`, `select`, `mutate`, `group_by`, and `order_by`.  

    Column values can also be changed using column operations such as `contains`, `upper`, or `like`.

    ---
    Table operations are methods on the `ir.Table` class. Some of the most common are:

    - [`filter`](https://ibis-project.org/reference/expression-tables#ibis.expr.types.relations.Table.filter) – keep rows that match a condition (like `WHERE` in SQL)  
    - [`select`](https://ibis-project.org/reference/expression-tables#ibis.expr.types.relations.Table.select) – choose columns or change their order  
    - [`mutate`](https://ibis-project.org/reference/expression-tables#ibis.expr.types.relations.Table.mutate) – add or modify columns  
    - [`order_by`](https://ibis-project.org/reference/expression-tables#ibis.expr.types.relations.Table.order_by) – sort rows by one or more columns  
    - [`group_by`](https://ibis-project.org/reference/expression-tables#ibis.expr.types.relations.Table.group_by) – group rows for aggregation  
    - [`join`](https://ibis-project.org/reference/expression-tables#ibis.expr.types.relations.Table.join) – combine rows from two tables based on a condition  

    ---

    Column operations work on individual fields inside a table expression.  
    They return a new column expression that can be used in `select`, `mutate`, or `filter`.  
    You can rename the result with `.alias("name")` or `.name("name")`.

    Some common column operations include:

    - *String operations*  
      Examples: `lower()`, `upper()`, `contains()`, `like()`, `substr()`  
      Useful for filtering or formatting text.

    - *Numeric operations*  
      Examples: `+`, `-`, `*`, `/`, `round()`, `floor()`, `ceil()`, `sum()`, `mean()`  
      Used for arithmetic, rounding, or aggregating.

    Column operations are the building blocks for most transformations.  
    You define how fields should be calculated, compared, or formatted, then combine them with table operations to build the query.

    ---

    All of these operations are *chained*, so the transformation is expressed as one pipeline:

    ```python
    result = (
        processes
        .filter(_.PID < 1000)
        .select(
            processes.ImageFileName.upper().name("image_file_name"), 
            processes.PID, 
            "Threads"
        )
        .mutate(pid=processes.PID)
        .order_by(_.Threads.desc())
        .head(10)
    )
    ```

    Next, we’ll look at some of these operations in more detail.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        rf"""
    ### Filter

    `filter` lets you keep only the rows that match a condition.  
    It works the same way as the `WHERE` clause in SQL.  

    For example, here we select only the processes with a PID less than 1000:
    """
    )
    return


@app.cell
def _(processes):
    processes.filter(processes.PID < 1000)
    return


@app.cell(hide_code=True)
def _():
    mo.md("""You can combine multiple filters using `&` (and) or `|` (or).""")
    return


@app.cell
def _(processes):
    processes.filter((processes.PID < 1000) & (processes.Threads > 5))
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""or by passing multiple conditions as arguments or in a list.""")
    return


@app.cell
def _(processes):
    processes.filter(
        processes.PID < 1000,
        processes.Threads > 5,
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        rf"""
    It can be useful to see the SQL that Ibis generates.  

    You can call `ibis.to_sql` on a table expression to inspect it.
    """
    )
    return


@app.cell
def _(processes):
    ibis.to_sql(
        processes.filter(
            processes.PID < 1000,
            processes.Threads > 5,
        )
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Note: The strange table name comes from Ibis automatically registering it in a temporary catalog. If you want a clearer name, you can pass one explicitly in `ibis.read_parquet`.""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        rf"""
    ### Exercise 3

    Filter the table for processes named *svchost.exe*.  

    Hint: use `filter` together with a condition on the `ImageFileName` column.
    """
    )
    return


@app.cell
def _():
    # Your code here... ✌️
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Solution": mo.md("""
                ```python
                  processes.filter(processes.ImageFileName == "svchost.exe")
                ```
            """)
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ### Exercise 4

    Find all processes whose name contains *TradingView* and that were created after `2024-04-17 10:50:00`.  

    Tip: use the [`contains`](https://ibis-project.org/reference/expression-strings#ibis.expr.types.strings.StringValue.contains) function to check if a string column contains a substring.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Solution": mo.md(
                """

            ```python
            date = datetime(2024, 4, 17, 10, 50, 0)

            processes.filter(
                processes.ImageFileName.contains("TradingView"),
                processes.CreateTime > date
            )
            ```

            which is converted to this SQL query

            ```sql
            SELECT
              *
            FROM "ibis_read_parquet_ie23lsr4cjgsfht22bokgi3sla" AS "t0"
            WHERE
              CONTAINS("t0"."ImageFileName", 'TradingView')
              AND "t0"."CreateTime" > MAKE_TIMESTAMP(2024, 4, 17, 10, 50, 0.0)

            ```

        """
            )
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        """
    ### Select

    Select specific columns from the processes table.

    Pass their names as strings:
    """
    )
    return


@app.cell
def _(processes):
    processes.select("PID", "ImageFileName", "Threads", "Handles")
    return


@app.cell(hide_code=True)
def _():
    mo.md("""Or use column objects directly:""")
    return


@app.cell
def _(processes):
    processes.select(
        processes.PID, processes.ImageFileName, processes.Threads
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        """
    ### Exercise 5

    Select the PID, PPID, and ImageFileName columns from the process table.
    """
    )
    return


@app.cell
def _():
    # Your code here...
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Solution": mo.md(
                """
            ```python
            processes.select("PID", "PPID", "ImageFileName")
            ```
        """
            )
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        """
    ### Drop

    Remove columns you don't need.  

    It is the opposite of select: instead of choosing what to keep, you name what to remove.

    You can pass:

    - strings (column names)
    - column objects
    - a mix of both
    """
    )
    return


@app.cell
def _(processes):
    processes.drop("CreateTime", "ExitTime", "Handles", "File output")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        """
    ### Mutate

    Create new columns. 
    Either from existing columns:
    """
    )
    return


@app.cell
def _(processes):
    processes.mutate(image_file_name=processes.ImageFileName.lower())
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Or from literal values:""")
    return


@app.cell
def _(processes):
    from datetime import datetime


    processes.mutate(analysis_date=datetime.now(), analyst_name=ibis.literal("Erika"))
    return (datetime,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ### Exercise 6

    Add two new columns:  

    1. *date* – take `CreateTime` and keep only the date (`YYYY-MM-DD`).
    2. *filename_length* – the number of characters in `ImageFileName`.


    Hint: use [`date`](https://ibis-project.org/reference/expression-temporal#ibis.date) and [`cast`](https://ibis-project.org/reference/expression-tables#ibis.expr.types.relations.Table.cast).
    """
    )
    return


@app.cell
def _():
    # Your code here...
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Solution": mo.md(
                """

            ```python

            processes.mutate(
                date = ibis.date(processes.CreateTime).cast("string"),
                filename_length = processes.ImageFileName.length()
            )
            ```

        """
            )
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        """
    ### Order By

    Sort rows using one or more columns.  By default, the sort is ascending.
    """
    )
    return


@app.cell
def _(processes):
    processes.order_by(processes.Threads)
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""But you can also do it in descending order.""")
    return


@app.cell
def _(processes):
    processes.order_by(processes.Threads.desc())
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""You can sort using multiple columns.""")
    return


@app.cell
def _(processes):
    processes.order_by(processes.Threads.desc(), processes.ImageFileName.lower())
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        """
    ## Method Chaining

    You can chain multiple transformations in one expression, or break them into steps with intermediate variables.
    """
    )
    return


@app.cell
def _(datetime, processes):
    t = (
        processes.select(
            "ImageFileName",
            "PID",
            "CreateTime",
        )
        .filter(processes.CreateTime > datetime(2023, 4, 17, 10, 50, 0))
        .order_by(processes.CreateTime)
        .rename("snake_case")  # rename columns, ImageFileName -> image_file_name
    )


    processes_with_low_pid = t.filter(t.pid < 100)
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""These are still lazy table expressions, so you can branch them in different ways without changing the original table.""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## The Deferred API `_`

    Before moving on to joins and groupings, it helps to know the deferred `_` API.  

    Ibis is built around chaining operations to build queries step by step.  
    The special `_` object makes this easier by standing in for the current table.  

    With `_`, you can refer to columns without writing the table name each time.  It works a bit like `self` in a class method.
    """
    )
    return


@app.cell
def _():
    from ibis import _
    return


@app.cell
def _(datetime, processes):
    (
        processes.select(
            _.ImageFileName,  # _ is the processes table
            _.PID,
            _.CreateTime,
        )
        .filter(_.CreateTime > datetime(2023, 4, 17, 10, 50, 0))
        .rename("snake_case")  # here we rename all columns from SnakeCase to snake_case
        .filter(_.pid < 100, _.image_file_name.contains(".exe"))
        .order_by(_.create_time.desc())
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ### Exercise 7

    Rewrite the query below to use the `_` API instead of the table name.  

    ```python
    (
        processes.select(
            "ImageFileName",
            "PID",
            "CreateTime",
        )
        .filter(processes.CreateTime > datetime(2023, 4, 17, 10, 50, 0))
        .order_by(processes.CreateTime)
        .rename("snake_case")
    )
    ```

    The call to `.rename("snake_case")` converts all column names,
    so `ImageFileName` becomes `image_file_name`.
    """
    )
    return


@app.cell
def _():
    ### Your code
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Solution": mo.md(
                """

            ```python
            (
                processes.select(
                    _.ImageFileName,
                    _.PID,
                    _.CreateTime,
                )
                .filter(_.CreateTime > datetime(2023, 4, 17, 10, 50, 0))
                .order_by(_.CreateTime)
                .rename("snake_case")  # rename columns, ImageFileName -> image_file_name
            )
            ```

        """
            )
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Great, now that we can write concise queries, let’s move on to aggregates and joins.""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        """
    ## Group By & Aggregate

    Use `group_by` to group rows that share the same value in one or more columns.  

    For example, here we group processes by `ImageFileName`:  

    ```python
    (
        processes
            .select(_.ImageFileName, _.CreateTime)
            .group_by(_.ImageFileName)
    )
    ```

    This returns a GroupedTable object, which you can inspect with mo.inspect.
    """
    )
    return


@app.cell
def _(processes):
    mo.inspect(
        processes
            .select(
                _.ImageFileName,
                _.CreateTime
            )
            .group_by(_.ImageFileName)
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    When we inspect the grouped table with `mo.inspect`,  we just see the groups, not the results.  

    To make it useful, we need to apply an aggregation. For example, we can count the number of rows in each group.
    """
    )
    return


@app.cell
def _(processes):
    (
        processes
            .select(_.ImageFileName, _.CreateTime)
            .group_by(_.ImageFileName)
            .aggregate(process_count=_.count())
            .order_by(_.process_count)
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""To filter groups after aggregation, use `having`.""")
    return


@app.cell
def _(processes):
    (
        processes
            .select(_.ImageFileName, _.CreateTime)
            .group_by(_.ImageFileName)
            .having(_.count() > 10)
            .aggregate(process_count=_.count())
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""It often helps readability to assign column expressions to variables, using `_` before building the query.""")
    return


@app.cell
def _(processes):
    _process_count = _.count() > 10

    (
        processes
            .select(_.ImageFileName, _.CreateTime)
            .group_by(_.ImageFileName)
            .having(_process_count)
            .aggregate(_process_count)
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    You can also write aggregations in shorter forms. 

    See the [docs](https://ibis-project.org/reference/expression-tables#ibis.expr.types.relations.Table.aggregate) for more details.  

    Here are some examples:
    """
    )
    return


@app.cell
def _(processes):
    _process_count = _.count() > 10

    (
        processes
            .select(_.ImageFileName, _.CreateTime)
            .aggregate(
                metrics=_process_count, 
                by=_.ImageFileName, 
                having=_process_count
        )
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    The full list of aggregation functions is in the [docs](https://ibis-project.org/reference/expression-generic#methods-1).  

    Let’s look at one of them, `collect`, which creates an array column with all values from each group.
    """
    )
    return


@app.cell
def _(processes):
    (
        processes
            .select(_.ImageFileName, _.CreateTime)
            .group_by(_.ImageFileName)
            .aggregate(creation_times=_.CreateTime.collect())
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Try writing a few more complex queries. 🌞""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ### Exercise 8

    For each process name (*ImageFileName*), find:

    - the highest *PID*
    - the first time it was spawned
    - the last time it was spawned

    Exclude names that appear only once.

    Hints:

    - Group by *ImageFileName*
    - Use `count()` in a `having` clause
    - Use `min()` and `max()` on *CreateTime*
    """
    )
    return


@app.cell
def _():
    # Your code ...
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Solution": mo.md(
                """

            ```python
            process_count = _.count()       
            (
                processes
                .group_by(_.ImageFileName)
                .having(process_count > 1)
                .aggregate(
                    max_pid    = _.PID.max(),
                    first_seen = _.CreateTime.min(),
                    last_seen  = _.CreateTime.max(),
                )
                .order_by(_.last_seen.desc())
            )
            ``` 
        """
            )
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ### Exercise 9

    The `windows.handles.Handles` plugin lists open handles per process.

    Create a compact summary that shows, for each process:

    - how many handles it has of each type
    - which unique names (objects/paths) those handles reference

    Hints:

    - group by process and handle type
    - use `collect()` with `unique()` to gather distinct names
    """
    )
    return


@app.cell
def _():
    handles = ibis.read_parquet("volatility_plugin_output/windows.handles.Handles.parquet")

    handles
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Solution": mo.md(
                """

            ```python
            (
                handles.group_by(_.PID, _.Process, _.Type)
                       .agg(n=_.count(), names=_.Name.collect().unique())
                       .order_by(_.PID, _.n.desc())
            )
            ``` 
        """
            )
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## Joins

    So far, we’ve only used the output of a single Volatility plugin.  
    To combine process details with network connections, we need a join.  

    A join merges rows from two tables based on matching columns.  
    The table you start with is the *left* table, and the one you add is the *right* table.  

    There are several join types (inner, left, right, outer, semi, anti).  
    The most common is the inner join, which keeps only rows where the key exists in both tables.  

    If the key has the same name in both tables:  
    ```python
    left.join(right, "key_column_name")
    ```

    If the keys have different names:

    ```python
    left.join(right, ("key_in_left", "key_in_right"))
    ```
    """
    )
    return


@app.cell
def _():
    netscan = ibis.read_parquet("volatility_plugin_output/windows.netscan.NetScan.parquet")
    return (netscan,)


@app.cell
def _(netscan, processes):
    processes.join(netscan, "PID")
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""As you see above, the result is a table with columns from both `pslist` and `netscan`.""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    To really show the value of joins, let’s add more plugin outputs:  

    - *privs* — lists the security privileges on each process token (e.g. `SeDebugPrivilege`, `SeImpersonatePrivilege`)  
    - *getsids* — lists the security identifiers (SIDs) linked to each process, showing which account or group owns it  

    By joining these on *PID*, we can ask deeper questions:  
    Which users are running which processes, and what privileges do those tokens have enabled?
    """
    )
    return


@app.cell
def _():
    sids = ibis.read_parquet("volatility_plugin_output/windows.getsids.GetSIDs.parquet")
    sids
    return


@app.cell
def _():
    privs = ibis.read_parquet("volatility_plugin_output/windows.privileges.Privs.parquet")
    privs
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ### Exercise 10

    Find processes that run under *non-SYSTEM user SIDs* and have *SeDebugPrivilege* enabled.

    For each user, also show *how many processes* they own with this privilege.

    Hints:

    - join `privs` and `sids` on `PID`
    - a privilege is enabled if `Attributes.contains("Present")`
    - non-SYSTEM user SIDs start with `S-1-5-21-`
    - use `mo.hstack` to place process details next to the per-user counts
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Solution": mo.md(
                """
                ```python
                processes_with_debug = (
                    privs
                      .filter(_.Privilege == "SeDebugPrivilege")
                      .filter(_.Attributes.contains("Present"))
                      .join(sids.filter(_.SID.startswith("S-1-5-21-")), "PID")
                      .select("PID", "Process", "SID", "Name")
                )

                users_with_debug = (
                    processes_with_debug
                      .group_by("SID", "Name")
                      .aggregate(
                          ProcessCount = _.PID.nunique(),
                      )
                )

                mo.hstack([processes_with_debug.drop("SID"), users_with_debug], widths="equal")
                ``` 
        """
            )
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Note: These processes shown here come from the memory acquisition itself (for example, *DumpIt.exe*).

    They only exist because the system was being dumped for forensics - a bit meta.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## Selectors

    Selectors let you pick columns by *pattern* (name) or *type* (data type).  
    They make code shorter and clearer, especially with wide tables.  

    Examples:  

    Select all numeric columns from a table `t`:  
          ```python
          t.select(s.numeric())
          ```
          Lowercase every string column with "filename" in its name (case-insensitive):
        ```python
        processes.mutate(
            s.across(
                s.of_type("string") & s.matches(r"(?i)filename"),
                _.lower()
            )
        )
        ```

    Selectors help keep code shorter and clearer, especially with wide tables.  
    See the Ibis blog post for more examples:  
    [https://ibis-project.org/posts/selectors/](https://ibis-project.org/posts/selectors/)  


    **Common selectors**

    - `s.cols(...)`, `s.contains(...)`, `s.startswith(...)`, `s.endswith(...)`, `s.matches(...)`
    - `s.numeric()` for numeric types
    - `s.across(selector, func|dict, names=...)` to apply transformations across many columns
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Let’s look at selectors in action.""")
    return


@app.cell
def _():
    import ibis.selectors as s
    return (s,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    The `malfind` plugin produces some very large columns, such as:  

    - `HexDump` - a binary dump of the VAD section where suspicious activity was found  
    - `Disasm` (or `DisasmString`) — the disassembled instructions from that region  

    These columns are useful for deep analysis but make tables harder to handle.  
    With selectors, you can drop or simplify them for a lighter view.
    """
    )
    return


@app.cell
def _():
    malfind = ibis.read_parquet("volatility_plugin_output/windows.malware.malfind.Malfind.parquet")
    malfind
    return (malfind,)


@app.cell(hide_code=True)
def _():
    mo.md(r"""Now let’s drop all columns with byte data, along with the `Disasm` column.""")
    return


@app.cell
def _(malfind, s):
    (
        malfind.select(
            ~s.of_type("bytes") & ~s.cols("Disasm")
        )
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    To show the flexibility of selectors, let’s explore a simple question: *what is the max length of each string column?*

    We will:

    - pick all string columns with `s.of_type("string")`
    - apply the same function to each with `s.across(...)`
    - compute `_.length().max()` and name outputs `"{col}_max_length"`
    """
    )
    return


@app.cell
def _(malfind, s):
    # compute max string length for every string column
    column_lengths = s.across(
        s.of_type("string"),
        _.length().max(),
        names="{col}_max_length",
    )

    malfind.aggregate(column_lengths)
    return (column_lengths,)


@app.cell(hide_code=True)
def _():
    mo.md(r"""Again, if you are curious, use `ibis.to_sql` to see exactly what is happening behind the scenes.""")
    return


@app.cell
def _(column_lengths, malfind):
    ibis.to_sql(malfind.aggregate(column_lengths))
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## Reusable code

    So far we’ve been writing queries and transformations directly in cells.  
    That works, but it quickly gets messy when you want to reuse the same logic more than once.  

    A cleaner approach is to put common patterns into small functions.  
    These functions should take a table or column as input, and return a new expression as output.  
    That way they stay pure and easy to reuse across cells or even across notebooks.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    One transformation that comes up often is renaming columns to `snake_case`.  
    Instead of typing the renaming logic each time, we can wrap it in a helper function  
    and apply it wherever we need.
    """
    )
    return


@app.function
def rename(t):
    return t.rename("snake_case")


@app.cell(hide_code=True)
def _():
    mo.md(r"""By using `pipe`, we can also chain this step with other transformations in a readable way.""")
    return


@app.cell
def _(malfind):
    malfind.pipe(rename)
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""We can keep calling pipe with more transformations. For example, if we want to rename values to be more succinct:""")
    return


@app.function
def abbr_protection_values(t):
    protection_mappings = {
        "PAGE_EXECUTE_READWRITE": "RWX",
        "PAGE_EXECUTE_READ": "RX",
        "PAGE_EXECUTE": "X",
        "PAGE_READWRITE": "RW",
        "PAGE_READONLY": "R",
        "PAGE_NOACCESS": "-",
    }

    mapping_expr = ibis.literal(protection_mappings)

    return t.mutate(protection=mapping_expr.get(t.protection, t.protection))


@app.cell
def _(malfind):
    m = malfind.pipe(rename).pipe(abbr_protection_values)

    m
    return (m,)


@app.cell(hide_code=True)
def _():
    mo.md(r"""Let's look at the SQL this emits?""")
    return


@app.cell
def _(m):
    ibis.to_sql(m)
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    <div align="center">
      <p>
        This is one reason we use <i>Ibis</i> here, not raw SQL. 😹
      </p>
    </div>
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.callout(
        mo.md(
            """### Ibis, SQL, and switch statements

            In SQL you’d normally use a `CASE` statement for branching logic.  Ibis gives you a few different ways to express the same thing:

            - *Lookup dictionary / map*  
              ```python
              mapping = {"A": 1, "B": 2}
              expr = mapping_expr.get(t.col, 0)
              ```
            - *.cases method* (simple case)  
              ```python
              expr = t.col.cases(
                  ("A", 1),
                  ("B", 2),
                  else_=0,
              )
              ```
            - *ibis.cases function* (searched case)  
              ```python
              expr = ibis.cases(
                  (t.col < 0, "neg"),
                  (t.col > 0, "pos"),
                  else_="zero",
              )
              ```
            - *.ifelse* (binary)  
              ```python
              expr = (t.col < 0).ifelse("neg", "non-neg")
              ```

            For more details refer to the docs: 

            - [Value.cases](https://ibis-project.org/reference/expression-generic#ibis.expr.types.generic.Value.cases)  
            - [ifelse](https://ibis-project.org/reference/expression-generic#ibis.ifelse)

          *Which one you choose* mostly comes down to clarity and personal taste.  
    The query optimizer should take care of the rest, and for small datasets  
    performance isn’t something to worry about.
            """
        )
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    We can do the same with column operations. 

    For example, the output from the `cmdline` plugin has a column called `Args`,  which stores the command line arguments as a single string.  Often we’ll want to split or filter on parts of this column,  so it makes sense to wrap those steps in small helpers too.
    """
    )
    return


@app.cell
def _():
    command_line = ibis.read_parquet("volatility_plugin_output/windows.cmdline.CmdLine.parquet")
    command_line
    return (command_line,)


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    It would also make sense to add a helper like `parse_command_line`.  

    This could be inspired by the [KQL function](https://learn.microsoft.com/en-us/kusto/query/parse-command-line-function?view=microsoft-fabric),  and mimic the behavior of [CommandLineToArgvW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw).  

    That way, instead of working with a raw string in the `Args` column,  we’d have a structured representation of the command line arguments, which is much easier to query and transform.
    """
    )
    return


@app.cell
def _(command_line):
    def _parse_command_line(args):
        args = (
                args
                .lower()
                .split(r" ")
                .name("command_line_arguments")
        )

        return args


    command_line.select(_parse_command_line(_.Args))
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ### Exercise 11

    Refine the `parse_command_line` function so that it cleans up the results.  

    Remove the first element (`argv[0]`, which is just the program name)  and apply `.strip()` to each of the remaining arguments.  

    *Hints*  

    - Use [map](https://ibis-project.org/reference/expression-collections#ibis.expr.types.arrays.ArrayValue.map) on the array column to apply `strip`.  
    - For array slicing you can use `[start:end]` just like in Python.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.accordion(
        {
            "Solution": mo.md("""
            ```python
            def parse_command_line(col):  
                args = col.lower().split(" ")
                args = args[1:] 
                args = args.map(lambda arg: arg.strip())

                return args.name("command_line_arguments")
            ```

            and then you can use like this:
            ```python
            command_line.mutate(parse_command_line(_.Args)) 
            ```
            """)
        }
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ## Referencing built-in functions

    Sometimes the backend has functions that Ibis does not expose yet.  You do not have to fall back to raw SQL. Instead, you can bind those functions to Ibis with the decorators:  

    - *`ibis.udf.scalar.builtin`* 
    - *`ibis.udf.agg.builtin`*.

    The idea is simple. You declare the function signature in Python. Ibis forwards the call to the backend function with the same name. This keeps your code readable and lets you stay in the expression API.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""Let's illustrate this by exposing the [parse_filename](https://duckdb.org/docs/stable/sql/functions/text#parse_filenamestring-trim_extension-separator) and [base64](https://duckdb.org/docs/stable/sql/functions/text#base64blob) DuckDB functions in Ibis.""")
    return


@app.cell
def _(command_line):
    @ibis.udf.scalar.builtin
    def parse_filename(path: str, trim_extension: bool = False, separator: str = "both_slash") -> str:
        """
        Returns the last component of the path similarly to Python's os.path.basename function.
        If trim_extension is true, the file extension will be removed (defaults to false).
        separator options: system, both_slash (default), forward_slash, backslash.
        """
        ...


    command_line.select(parse_filename(_.Process))
    return


@app.cell
def _(command_line):
    @ibis.udf.scalar.builtin
    def base64(b: bytes) -> str:
        """
        Converts a blob to a base64 encoded string.
        """
        ...


    command_line.select(base64(_.Process.cast("bytes")))
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""This is a powerful feature, since DuckDB has a lot of extensions that we can use.""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    ### Python UDFs

    So far we’ve only seen how to *wrap existing DuckDB functions* so they can be called from Ibis.  That’s handy, but sometimes you need logic that isn’t available as a built-in.  In that case, you can write your own *pure Python UDF*.  

    Ibis provides the `@ibis.udf.scalar.python` decorator for this.  
    These functions run row by row in CPython. Each value is copied from DuckDB into Python, so they are not the most efficient option.  

    For our Volatility datasets, which are fairly small, this overhead is fine.  If you did need more speed, Ibis also supports `@ibis.udf.scalar.pyarrow`.  Those UDFs work on batches of Arrow arrays instead of single values, which avoids most of the Python call overhead.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Let’s illustrate this with a real example.  

    The `malfind` plugin in Volatility produces two related columns: *`Hexdump`* (the raw bytes) and *`Disasm`* (the corresponding disassembly).  

    We can recreate that second column by writing a custom Python UDF that calls [Capstone](https://www.capstone-engine.org/) to disassemble the bytes stored in `Hexdump`.  

    The output should line up with the existing `Disasm` column, since Volatility uses  the same disassembly process internally.
    """
    )
    return


@app.cell
def _(malfind):
    malfind.select(_.Hexdump, _.Disasm)
    return


@app.cell
def _():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    md = Cs(CS_ARCH_X86, CS_MODE_64)


    @ibis.udf.scalar.python
    def disasm(code: bytes, offset: int) -> str:
        """
        Disassemble raw bytes with Capstone.

        Parameters
        ----------
        code : bytes
            Raw machine code (Hexdump column).
        offset : int
            Virtual address to start disassembly from.
            Controls the printed instruction addresses.
        """
        instructions = []

        # disasm_lite yields (address, size, mnemonic, operands)
        for address, size, mnemonic, op_str in md.disasm_lite(code, offset=offset):
            formatted = f"0x{address:x}:\t{mnemonic}\t{op_str}"
            instructions.append(formatted)

        return "\n".join(instructions)
    return (disasm,)


@app.cell
def _(disasm, malfind):
    malfind.select(
        _.Disasm,
        disasm=disasm(_.Hexdump, malfind["Start VPN"].cast("int")),
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Take note of this: you’re not limited to what Ibis or DuckDB provide out of the box.  

    You can wrap and call into any third-party Python package. That opens the door to a huge range of libraries, from security tools to data science utilities.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""---""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    This was *a lot* of information to take in at once.  

    Don’t worry if some of it didn’t sink in, the next notebooks will give you plenty of chances to practice and come back to these ideas.  

    <div align="center">
        <p>It's time to get back to memory forensics.<br/></p>
    </div>
    """
    )
    return


if __name__ == "__main__":
    app.run()
