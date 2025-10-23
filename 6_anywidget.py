# /// script
# [tool.marimo.display]
# theme = "light"
# ///

import marimo

__generated_with = "0.16.0"
app = marimo.App(width="medium", app_title="AnyWidget", css_file="")

with app.setup(hide_code=True):
    import ibis
    import json
    import anywidget
    import traitlets
    import marimo as mo

    from ibis import _
    from datetime import datetime

    from process_tree_widget import ProcessTreeWidget
    from process_tree_widget.tree import Process, ProcessTree

    ibis.options.interactive = True


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    <div align="center">
      <img src="public/anywidget.png" style="max-width: 500px; margin-bottom: -20px;"/>
      <p>Custom visualizations using <a href="https://marimo.io/blog/anywidget">anywidget</a></p>
    </div>

    Libraries like [Altair](https://altair-viz.github.io/) are excellent 
    for traditional data visualization, but sometimes you want to go beyond standard plots.  

    If you need a *purpose-built, deeply interactive UI* - a custom control or visualization tied 
    directly to your data, then `anywidget` is the right tool.  

    marimo has first-class support for [anywidget](https://anywidget.dev), a lightweight way to build **custom interactive widgets**.  

    There is *a lot* more to anywidget than we will discuss here, so check out the project’s website for details.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    At a high level, an anywidget pairs **Python state** with a **browser UI**.  
    You declare state in Python with `traitlets`; you render and handle interactivity in JavaScript.  
    anywidget keeps the two sides synchronized so changes on one side immediately show up on the other.

    An anywidget consists of two synchronized parts:

    - **Python** defines state with `traitlets`.
    - **JavaScript** renders the UI and handles interactivity in the browser.

    This makes it straightforward to combine Python data with custom DOM

    **Python side**

    Subclass `anywidget.AnyWidget` and declare stateful properties.  
    Traits tagged with `.tag(sync=True)` stay synchronized with the frontend.

    ```python
    import anywidget, traitlets

    class Widget(anywidget.AnyWidget):
        # state that syncs with the frontend
        some_state = traitlets.Int(0).tag(sync=True)
    ```

    **JavaScript side** 

    Export a small ES module as shown below. 

    Most widgets only need `render({ model, el })`; `initialize` is optional.

    ```js
    export default {
      initialize({ model }) {
        // called once per widget instance
        return () => {
          // cleanup
        };
      },
      render({ model, el }) {
        // draw into el; read/write state via model
        return () => {
          // cleanup on re-render
        };
      },
    };
    ```

    **State flow**

    The host (marimo, Jupyter, VS Code) wires Python traits to the JS model so state flows both ways:

    - **Python → JS**: Python updates a trait → the frontend reflects it.
    - **JS → Python**: Frontend calls `model.set(...)`; `model.save_changes()`; → Python sees the change.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    It's easier to just show how it works, so let’s re-implement the [Build a Counter Widget](https://anywidget.dev/en/notebooks/counter/) example from the official documentation, but add some ✨ extra flair ✨.  

    What we want is to create a Widget that keeps track of how many times we have clicked a button (the `count`, and once the counter reach `10` we trigger a confettio animation. 

    This is how it breaks down:

    - On the Python side, we define a `count` trait that stays synchronized with the frontend.  
    - On the JavaScript side, we render a styled button that increments the counter and keeps both the widget UI and Python in sync whenever it’s clicked.
    """
    )
    return


@app.class_definition
class Counter(anywidget.AnyWidget):
    _esm = r"""
    import { html } from "https://esm.sh/htl@latest";
    import confetti from "https://esm.sh/canvas-confetti@latest";

    function render({ model, el }) {
      const count = () => model.get("count");

      const btn = html`<button class="counter-btn"
        ${{
          onclick() {
            model.set("count", count() + 1);
            model.save_changes();

            if (count() == 10) 
                confetti();
          }
        }}
      >
        count = <span class="val"></span>
      </button>`;

      const valEl = btn.querySelector(".val");
      const update = () => { valEl.textContent = count(); };
      update(); // initial render
      model.on("change:count", update);

      el.append(btn);
    }

    export default { render };
    """

    _css = r"""
    .counter-btn {
      background: #4a90e2;
      color: white;
      padding: 8px 20px;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
    }

    .counter-btn:hover {
      background: #357ab8;
    }
    """

    count = traitlets.Int(0).tag(sync=True)


@app.cell
def _():
    counter = mo.ui.anywidget(Counter())
    counter
    return (counter,)


@app.cell
def _(counter):
    counter.count
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        """
    In the example above we used a couple of things worth calling out. For example, we imported the `htl` module in a slightly unusual way:

    ```js
    import { html } from "https://esm.sh/htl@latest";
    ```

    What’s happening here is that we’re not installing `htl` as a local dependency - instead we’re pulling it straight from a CDN as a ready-to-use ES module.  
    [esm.sh](https://esm.sh/) is a CDN that takes NPM packages and serves them as browser-ready ES modules.  
    That’s why we can import `htl` directly into our widget, without setting up a local build step.

    And when it comes to the actual module we import:

    - [htl](https://github.com/observablehq/htl) is a small library from Observable for declaratively building DOM elements with template literals.  
      It safely interpolates variables, event listeners, styles, and DOM nodes - much nicer than writing `document.createElement` by hand.

    For smaller widgets or quick demos, you can keep `_esm` (JavaScript) and `_css` (styles) inline in your widget class.  
    For larger widgets, it’s common to split Python, JS, and CSS into separate files and bundle them into a single ES module (see the [bundling guide](https://anywidget.dev/en/bundling/)).  
    In that case, point `_esm_path` (and optionally `_css_path`) to the built file so marimo can load it.
    """
    )
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    Okay, so that counter widget was a cute example. To give a sense of how this looks in a real production setting, let’s look at our **interactive process tree visualization**, which we have described in detail in the this blog post - 
    [Visualizing process trees with marimo and anywidget](https://blog.cauchy.org/blog/anywidget/).

    In the arcticle, we show how to wrap the JavaScript library [dependentree](https://github.com/square/dependentree/) in anywidget and use it to render an interactive process tree. 

    The same idea can then be reused with memory forensics data by taking the output from the `pstree` plugin.
    """
    )
    return


@app.cell
def _():
    pstree = ibis.read_parquet("volatility_plugin_output/windows.pstree.PsTree.parquet")
    return (pstree,)


@app.cell
def _(pstree):
    widget = mo.ui.anywidget(ProcessTreeWidget(events=pstree, source="volatility", show_timefilter=True))
    widget
    return (widget,)


@app.cell
def _(widget):
    widget.process_id
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""As you can the `process_id` value is syncronized between the backend and the frontend code, so we use to continue investigating the data. For example, we can display the just the DLLs that are loaded by the selected process.""")
    return


@app.cell
def _():
    dll = ibis.read_parquet("volatility_plugin_output/windows.dlllist.DllList.parquet")
    return (dll,)


@app.cell
def _(dll, widget):
    dll.filter(_.PID == widget.process_id)
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""It would have been a nice with graph representation of this data. In order to demonstrate how can quickly throw something together lets do a small example of that using [sigma.js](https://www.sigmajs.org/) and [grapology](https://github.com/graphology/graphology).""")
    return


@app.cell
def _():
    esm = """
        import { html } from "https://esm.sh/htl@latest";
        import graphology from "https://esm.sh/graphology@latest";
        import forceAtlas2 from "https://esm.sh/graphology-layout-forceatlas2@latest";
        import Sigma from "https://esm.sh/sigma@latest";

        function render({ model, el }) {

          const div = html`
              <div class="main">
                <div class="container"></div>
              </div>
          `;

          el.append(div);

          const rows = model.get("nodes") || [];
      const G = new graphology.MultiGraph({ allowSelfLoops: false });

      const pidId = (pid) => `p:${pid}`;
      const dllId = (name, path) =>
        `d:${(name || "").toLowerCase()}|${(path || "").toLowerCase()}`;

      for (const { PID, Process, Name, Path, Base } of rows) {
        const p = pidId(PID);
        if (!G.hasNode(p)) {
          G.addNode(p, {
            role: "proc",
            label: Process ? `${Process} (${PID})` : String(PID),
            size: 8,
            color: "#4C78A8",
          });
        }

        const d = dllId(Name, Path);
        if (!G.hasNode(d)) {
          G.addNode(d, {
            role: "dll",
            label: Name || "(dll)",
            size: 6,
            color: "#72B7B2",
          });
        }

        G.addEdge(p, d, { color: "#B4BDC7", size: 1.2, base: Base ?? null });
      }

      // Seed + layout
      G.forEachNode((n) => {
        G.setNodeAttribute(n, "x", Math.random());
        G.setNodeAttribute(n, "y", Math.random());
      });
      forceAtlas2.assign(G, { iterations: 800 });

      new Sigma(G, div.querySelector(".container"));

        }

        export default { render };
    """
    return (esm,)


@app.cell
def _():
    css = """

    .main {
      width: 900px;
      height: 600px;
      border: 1px solid #d6d6d6;
      border-radius: 6px;
      position: relative;
      font: 12px system-ui, sans-serif;
    }

    .container {
      height: 100%;
      width: 100%;
    }


    """
    return (css,)


@app.cell
def _(css, esm):
    class DllGraph(anywidget.AnyWidget):
        _esm = esm
        _css = css

        nodes = traitlets.List([]).tag(sync=True)

        def __init__(self, events, **kwargs):
            super().__init__(**kwargs)
            self.nodes = events.to_pyarrow().to_pylist()
    return (DllGraph,)


@app.cell
def _(DllGraph, dll, widget):
    _dlls = dll.filter(_.PID == widget.process_id)
    _dll_count = _dlls.count().execute()

    # use tenary operator so the statement "returns" a value
    mo.plain_text("No dlls for this process") if _dll_count == 0 else mo.ui.anywidget(DllGraph(events=_dlls))
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""It's a bit *yanky*, but it's pretty cool how powerful these tools are and you throw something together like this relatively easily.""")
    return


@app.cell(hide_code=True)
def _():
    mo.md(
        r"""
    And with that the workshop comes to a close. We covered a lot together, and the whole point was just to spark ideas for how you can start building your own tools.

    We skipped over plenty of details, but hopefully you now feel inspired to dig into the resources we linked and see that so much of this is possible once you give it a try.  

    You’ve got a whole toolbox at your fingertips now. Thank you for following along! Please share what you build in the discord, on LinkedIn, or wherever you like and we’ll open source the tutorial and make the video publically available soon.  

    Can’t wait to see what you create!  

    <div align="center">
      <p>🌞</p>
    </div>
    """
    )
    return


if __name__ == "__main__":
    app.run()
